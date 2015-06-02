/*
 * Copyright © 2015 Broadcom
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#define LOG_TAG "GRALLOC-VC4"

#include <cutils/log.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>
#include <drm.h>

#include "gralloc_drm.h"
#include "gralloc_drm_priv.h"

struct vc4_drv {
	struct gralloc_drm_drv_t base;

	int fd;
};

struct vc4_bo {
	struct gralloc_drm_bo_t base;

	uint32_t handle;
	uint32_t size;

	void *map;
};

bool
vc4_bo_wait(struct gralloc_drm_drv_t *drv, struct gralloc_drm_bo_t *bo,
	    uint64_t timeout_ns)
{
	struct vc4_drv *vc4_drv = (struct vc4_drv *) drv;
	struct vc4_bo *vc4_bo = (struct vc4_bo *) bo;

        struct drm_vc4_wait_bo wait;
        memset(&wait, 0, sizeof(wait));
        wait.handle = vc4_bo->handle;
        wait.timeout_ns = timeout_ns;

        int ret = drmIoctl(vc4_drv->fd, DRM_IOCTL_VC4_WAIT_BO, &wait);

        if (ret == 0)
                return true;

        if (errno != ETIME)
                ALOGE("wait failed: %d\n", ret);

        return false;
}

static struct gralloc_drm_bo_t *
vc4_alloc(struct gralloc_drm_drv_t *drv, struct gralloc_drm_handle_t *handle)
{
	struct vc4_drv *vc4_drv = (struct vc4_drv *) drv;
	struct vc4_bo *vc4_bo;
	int cpp;

	cpp = gralloc_drm_get_bpp(handle->format);
	if (!cpp) {
		ALOGE("unrecognized format 0x%x", handle->format);
		return NULL;
	}

	vc4_bo = calloc(1, sizeof(*vc4_bo));
	if (!vc4_bo)
		return NULL;

	if (handle->name) {
		struct drm_gem_open o = {
			.name = handle->name
		};
		int ret = drmIoctl(vc4_drv->fd, DRM_IOCTL_GEM_OPEN, &o);
		if (ret) {
			ALOGE("Failed to open bo %d: %s\n",
			      handle->name, strerror(errno));
			free(vc4_bo);
			return NULL;
		}

		vc4_bo->handle = o.handle;
		vc4_bo->size = o.size;
	} else {
		int width, height;
		uint32_t pitch;

		width = handle->width;
		height = handle->height;
		gralloc_drm_align_geometry(handle->format, &width, &height);

		/* XXX: Fix pitch alignment.  Handle tiling.  Etc. */
		pitch = ALIGN(width, 32) * cpp;
		uint32_t size = pitch * height;

		struct drm_vc4_create_bo create = {
			.size = size,
		};

		int ret = drmIoctl(vc4_drv->fd, DRM_IOCTL_VC4_CREATE_BO,
				   &create);
		if (ret) {
			ALOGE("failed to allocate vc4 bo %dx%dx%d",
			      handle->width, handle->height, cpp);
			free(vc4_bo);
			return NULL;
		}

		vc4_bo->handle = create.handle;
		vc4_bo->size = size;

		struct drm_gem_flink flink = {
			.handle = vc4_bo->handle,
		};
		ret = drmIoctl(vc4_drv->fd, DRM_IOCTL_GEM_FLINK, &flink);
		if (ret) {
			ALOGE("Failed to flink bo %d: %s\n",
			      vc4_bo->handle, strerror(errno));
			free(vc4_bo);
			return NULL;
		}

		handle->name = flink.name;
	}

	if (handle->usage & GRALLOC_USAGE_HW_FB)
		vc4_bo->base.fb_handle = vc4_bo->handle;

	vc4_bo->base.handle = handle;

	return &vc4_bo->base;
}

static void vc4_free(struct gralloc_drm_drv_t *drv,
		     struct gralloc_drm_bo_t *bo)
{
	struct vc4_drv *vc4_drv = (struct vc4_drv *) drv;
	struct vc4_bo *vc4_bo = (struct vc4_bo *) bo;

	if (vc4_bo->map)
		munmap(vc4_bo->map, vc4_bo->size);

	struct drm_gem_close c = {
		.handle = vc4_bo->handle,
	};
        int ret = drmIoctl(vc4_drv->fd, DRM_IOCTL_GEM_CLOSE, &c);
        if (ret != 0)
                ALOGE("close object %d: %s\n", vc4_bo->handle, strerror(errno));

	free(vc4_bo);
}

static int vc4_map(struct gralloc_drm_drv_t *drv,
		   struct gralloc_drm_bo_t *bo, int x, int y, int w, int h,
		   int enable_write, void **addr)
{
	struct vc4_drv *vc4_drv = (struct vc4_drv *) drv;
	struct vc4_bo *vc4_bo = (struct vc4_bo *) bo;

	if (!vc4_bo->map) {
                struct drm_vc4_mmap_bo map = {
			.handle = vc4_bo->handle,
		};
                int ret = drmIoctl(vc4_drv->fd, DRM_IOCTL_VC4_MMAP_BO, &map);
		if (ret) {
			ALOGE("Failed to map BO\n");
			return -errno;
		}

		vc4_bo->map = mmap(NULL, vc4_bo->size, PROT_READ | PROT_WRITE,
				   MAP_SHARED, vc4_drv->fd, map.offset);
		if (vc4_bo->map == MAP_FAILED) {
			ALOGE("mmap of bo %d (offset 0x%016llx, size %d) "
			      "failed\n",
			      vc4_bo->handle, (long long)map.offset,
			      vc4_bo->size);
			return -errno;
		}
	}

	/* Wait for any previous rendering before returning the
	 * mapping.
	 */
	if (!vc4_bo_wait(drv, bo, ~0ull))
		return -errno;

	*addr = vc4_bo->map;
	return 0;
}

static void vc4_unmap(struct gralloc_drm_drv_t *drv,
		struct gralloc_drm_bo_t *bo)
{
	/* We don't munmap because it's expensive to re-map it later. */
}

static void vc4_init_kms_features(struct gralloc_drm_drv_t *drv,
				  struct gralloc_drm_t *drm)
{
	struct vc4_drv *info = (struct vc4_drv *) drv;

	/* XXX: Add more formats. */
	switch (drm->primary.fb_format) {
	case HAL_PIXEL_FORMAT_BGRA_8888:
		break;
	default:
		drm->primary.fb_format = HAL_PIXEL_FORMAT_BGRA_8888;
		break;
	}

	drm->swap_mode = DRM_SWAP_COPY; /* XXX: For now. */
	drm->mode_sync_flip = 1;
	drm->swap_interval = 1;
	drm->vblank_secondary = 0;
}

static void vc4_destroy(struct gralloc_drm_drv_t *drv)
{
	struct vc4_drv *info = (struct vc4_drv *) drv;
	close(info->fd);
	free(info);
}

struct gralloc_drm_drv_t *gralloc_drm_drv_create_for_vc4(int fd)
{
	struct vc4_drv *vc4_drv;
	int err;

	vc4_drv = calloc(1, sizeof(*vc4_drv));
	if (!vc4_drv)
		return NULL;

	vc4_drv->fd = dup(fd);
	vc4_drv->base.destroy = vc4_destroy;
	vc4_drv->base.init_kms_features = vc4_init_kms_features;
	vc4_drv->base.alloc = vc4_alloc;
	vc4_drv->base.free = vc4_free;
	vc4_drv->base.map = vc4_map;
	vc4_drv->base.unmap = vc4_unmap;

	return &vc4_drv->base;
}
