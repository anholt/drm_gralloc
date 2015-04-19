/*
 * Copyright (C) 2011 Chia-I Wu <olvaffe@gmail.com>
 * Copyright (C) 2011 LunarG Inc.
 * Copyright (C) 2014 Rob Clark <robclark@freedesktop.org>
 *
 * Based on xf86-video-nouveau, which has
 *
 * Copyright © 2007 Red Hat, Inc.
 * Copyright © 2008 Maarten Maathuis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#define LOG_TAG "GRALLOC-FREEDRENO"

#include <cutils/log.h>
#include <stdlib.h>
#include <errno.h>
#include <drm.h>
#include <freedreno_drmif.h>

#include "gralloc_drm.h"
#include "gralloc_drm_priv.h"

struct fd_info {
	struct gralloc_drm_drv_t base;

	int fd;
	struct fd_device *dev;
};

struct fd_buffer {
	struct gralloc_drm_bo_t base;

	struct fd_bo *bo;
};

static struct fd_bo *alloc_bo(struct fd_info *info,
		int width, int height, int cpp, int usage, int *pitch)
{
	struct fd_bo *bo = NULL;
	int flags, size;

	/* TODO need a scanout flag if (usage & GRALLOC_USAGE_HW_FB).. */
	flags = DRM_FREEDRENO_GEM_CACHE_WCOMBINE;

	*pitch = ALIGN(width, 32) * cpp;
	size = *pitch * height;

	return fd_bo_new(info->dev, size, flags);
}

static struct gralloc_drm_bo_t *
fd_alloc(struct gralloc_drm_drv_t *drv, struct gralloc_drm_handle_t *handle)
{
	struct fd_info *info = (struct fd_info *) drv;
	struct fd_buffer *fd_buf;
	int cpp;

	cpp = gralloc_drm_get_bpp(handle->format);
	if (!cpp) {
		ALOGE("unrecognized format 0x%x", handle->format);
		return NULL;
	}

	fd_buf = calloc(1, sizeof(*fd_buf));
	if (!fd_buf)
		return NULL;

	if (handle->name) {
		fd_buf->bo = fd_bo_from_name(info->dev, handle->name);
		if (!fd_buf->bo) {
			ALOGE("failed to create fd bo from name %u",
					handle->name);
			free(fd_buf);
			return NULL;
		}
	}
	else {
		int width, height, pitch;

		width = handle->width;
		height = handle->height;
		gralloc_drm_align_geometry(handle->format, &width, &height);

		fd_buf->bo = alloc_bo(info, width, height,
				cpp, handle->usage, &pitch);
		if (!fd_buf->bo) {
			ALOGE("failed to allocate fd bo %dx%dx%d",
					handle->width, handle->height, cpp);
			free(fd_buf);
			return NULL;
		}

		if (fd_bo_get_name(fd_buf->bo, (uint32_t *) &handle->name)) {
			ALOGE("failed to flink fd bo");
			fd_bo_del(fd_buf->bo);
			free(fd_buf);
			return NULL;
		}

		handle->stride = pitch;
	}

	if (handle->usage & GRALLOC_USAGE_HW_FB)
		fd_buf->base.fb_handle = fd_bo_handle(fd_buf->bo);

	fd_buf->base.handle = handle;

	return &fd_buf->base;
}

static void fd_free(struct gralloc_drm_drv_t *drv,
		struct gralloc_drm_bo_t *bo)
{
	struct fd_buffer *fd_buf = (struct fd_buffer *) bo;
	fd_bo_del(fd_buf->bo);
	free(fd_buf);
}

static int fd_map(struct gralloc_drm_drv_t *drv,
		struct gralloc_drm_bo_t *bo, int x, int y, int w, int h,
		int enable_write, void **addr)
{
	struct fd_buffer *fd_buf = (struct fd_buffer *) bo;
	if (fd_bo_map(fd_buf->bo))
		return 0;
	return -errno;
}

static void fd_unmap(struct gralloc_drm_drv_t *drv,
		struct gralloc_drm_bo_t *bo)
{
	// TODO should add fd_bo_unmap() to libdrm_freedreno someday..
}

static void fd_init_kms_features(struct gralloc_drm_drv_t *drv,
		struct gralloc_drm_t *drm)
{
	struct fd_info *info = (struct fd_info *) drv;

	switch (drm->primary.fb_format) {
	case HAL_PIXEL_FORMAT_BGRA_8888:
	case HAL_PIXEL_FORMAT_RGB_565:
		break;
	default:
		drm->primary.fb_format = HAL_PIXEL_FORMAT_BGRA_8888;
		break;
	}

	drm->mode_quirk_vmwgfx = 0;
	drm->swap_mode = DRM_SWAP_FLIP;
	drm->mode_sync_flip = 1;
	drm->swap_interval = 1;
	drm->vblank_secondary = 0;
}

static void fd_destroy(struct gralloc_drm_drv_t *drv)
{
	struct fd_info *info = (struct fd_info *) drv;
	fd_device_del(info->dev);
	free(info);
}

struct gralloc_drm_drv_t *gralloc_drm_drv_create_for_freedreno(int fd)
{
	struct fd_info *info;
	int err;

	info = calloc(1, sizeof(*info));
	if (!info)
		return NULL;

	info->fd = fd;
	info->dev = fd_device_new_dup(info->fd);
	if (!info->dev) {
		ALOGE("failed to create fd device");
		free(info);
		return NULL;
	}

	info->base.destroy = fd_destroy;
	info->base.init_kms_features = fd_init_kms_features;
	info->base.alloc = fd_alloc;
	info->base.free = fd_free;
	info->base.map = fd_map;
	info->base.unmap = fd_unmap;

	return &info->base;
}