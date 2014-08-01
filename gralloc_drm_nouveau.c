/*
 * Copyright (C) 2011 Chia-I Wu <olvaffe@gmail.com>
 * Copyright (C) 2011 LunarG Inc.
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

#define LOG_TAG "GRALLOC-NOUVEAU"

#include <cutils/log.h>
#include <stdlib.h>
#include <errno.h>
#include <drm.h>
#include <nouveau.h>

#include "gralloc_drm.h"
#include "gralloc_drm_priv.h"

#define NV_ARCH_03  0x03
#define NV_ARCH_04  0x04
#define NV_ARCH_10  0x10
#define NV_ARCH_20  0x20
#define NV_ARCH_30  0x30
#define NV_ARCH_40  0x40
#define NV_TESLA    0x50
#define NV_FERMI    0xc0
#define NV_KEPLER   0xe0
#define NV_MAXWELL  0x110

#define NV50_TILE_HEIGHT(m) (4 << ((m) >> 4))
#define NVC0_TILE_HEIGHT(m) (8 << ((m) >> 4))

struct nouveau_info {
	struct gralloc_drm_drv_t base;

	int fd;
	uint32_t arch;
	struct nouveau_device *dev;
	struct nouveau_client *client;
	struct nouveau_object *channel;
	struct nouveau_pushbuf *pushbuf;
};

struct nouveau_buffer {
	struct gralloc_drm_bo_t base;

	struct nouveau_bo *bo;
};

static struct nouveau_bo *alloc_bo(struct nouveau_info *info,
		int width, int height, int cpp, int usage, int *pitch)
{
	struct nouveau_bo *bo = NULL;
	union nouveau_bo_config cfg = {};
	int flags;
	int tiled, scanout;
	unsigned int align;

	flags = NOUVEAU_BO_MAP | NOUVEAU_BO_VRAM;

	scanout = !!(usage & GRALLOC_USAGE_HW_FB);

	tiled = !(usage & (GRALLOC_USAGE_SW_READ_OFTEN |
			   GRALLOC_USAGE_SW_WRITE_OFTEN));

	if (info->arch >= NV_TESLA) {
		tiled = 1;
		align = 64;
	}
	else {
		if (scanout)
			tiled = 1;
		align = 64;
	}

	*pitch = ALIGN(width * cpp, align);

	if (tiled) {
		if (info->arch >= NV_FERMI) {
			if (height > 64)
				cfg.nvc0.tile_mode = 0x0040;
			else if (height > 32)
				cfg.nvc0.tile_mode = 0x0030;
			else if (height > 16)
				cfg.nvc0.tile_mode = 0x0020;
			else if (height > 8)
				cfg.nvc0.tile_mode = 0x0010;
			else
				cfg.nvc0.tile_mode = 0x0000;

			cfg.nvc0.memtype = 0x00fe;

			align = NVC0_TILE_HEIGHT(cfg.nvc0.tile_mode);
			height = ALIGN(height, align);
		}
		else if (info->arch >= NV_TESLA) {
			if (height > 32)
				cfg.nv50.tile_mode = 0x0040;
			else if (height > 16)
				cfg.nv50.tile_mode = 0x0030;
			else if (height >  8)
				cfg.nv50.tile_mode = 0x0020;
			else if (height >  4)
				cfg.nv50.tile_mode = 0x0010;
			else
				cfg.nv50.tile_mode = 0x0000;

			cfg.nv50.memtype = (scanout && cpp != 2) ?
					0x007a : 0x0070;

			align = NV50_TILE_HEIGHT(cfg.nv50.tile_mode);
			height = ALIGN(height, align);
		}
		else {
			align = *pitch / 4;

			/* round down to the previous power of two */
			align >>= 1;
			align |= align >> 1;
			align |= align >> 2;
			align |= align >> 4;
			align |= align >> 8;
			align |= align >> 16;
			align++;

			align = MAX((info->dev->chipset >= NV_ARCH_40) ?
					1024 : 256, align);

			/* adjust pitch */
			*pitch = ALIGN(*pitch, align);
			cfg.nv04.surf_pitch = *pitch;
		}
	}

	if (info->arch < NV_TESLA) {
		if (cpp == 4)
			cfg.nv04.surf_flags |= NV04_BO_32BPP;
		else if (cpp == 2)
			cfg.nv04.surf_flags |= NV04_BO_16BPP;
	}

	if (scanout)
		flags |= NOUVEAU_BO_CONTIG;

	if (nouveau_bo_new(info->dev, flags, 0, *pitch * height, &cfg, &bo)) {
		ALOGE("failed to allocate bo (flags 0x%x, size %d)",
				flags, *pitch * height);
		bo = NULL;
	}

	return bo;
}

static struct gralloc_drm_bo_t *nouveau_alloc(struct gralloc_drm_drv_t *drv,
		struct gralloc_drm_handle_t *handle)
{
	struct nouveau_info *info = (struct nouveau_info *) drv;
	struct nouveau_buffer *nb;
	int cpp;

	cpp = gralloc_drm_get_bpp(handle->format);
	if (!cpp) {
		ALOGE("unrecognized format 0x%x", handle->format);
		return NULL;
	}

	nb = calloc(1, sizeof(*nb));
	if (!nb)
		return NULL;

	if (handle->name) {
		if (nouveau_bo_name_ref(info->dev, handle->name, &nb->bo)) {
			ALOGE("failed to create nouveau bo from name %u",
					handle->name);
			free(nb);
			return NULL;
		}
	}
	else {
		int width, height, pitch;

		width = handle->width;
		height = handle->height;
		gralloc_drm_align_geometry(handle->format, &width, &height);

		nb->bo = alloc_bo(info, width, height, cpp,
				  handle->usage, &pitch);
		if (!nb->bo) {
			ALOGE("failed to allocate nouveau bo %dx%dx%d",
					handle->width, handle->height, cpp);
			free(nb);
			return NULL;
		}

		if (nouveau_bo_name_get(nb->bo,
					(uint32_t *) &handle->name)) {
			ALOGE("failed to flink nouveau bo");
			nouveau_bo_ref(NULL, &nb->bo);
			free(nb);
			return NULL;
		}

		handle->stride = pitch;
	}

	if (handle->usage & GRALLOC_USAGE_HW_FB)
		nb->base.fb_handle = nb->bo->handle;

	nb->base.handle = handle;

	return &nb->base;
}

static void nouveau_free(struct gralloc_drm_drv_t *drv,
		struct gralloc_drm_bo_t *bo)
{
	struct nouveau_buffer *nb = (struct nouveau_buffer *) bo;
	nouveau_bo_ref(NULL, &nb->bo);
	free(nb);
}

static int nouveau_map(struct gralloc_drm_drv_t *drv,
		struct gralloc_drm_bo_t *bo, int x, int y, int w, int h,
		int enable_write, void **addr)
{
	struct nouveau_info *info = (struct nouveau_info *) drv;
	struct nouveau_buffer *nb = (struct nouveau_buffer *) bo;
	uint32_t flags;
	int err;

	flags = NOUVEAU_BO_RD;
	if (enable_write)
		flags |= NOUVEAU_BO_WR;

	/* TODO if tiled, allocate a linear copy of bo in GART and map it */
	err = nouveau_bo_map(nb->bo, flags, info->client);
	if (!err)
		*addr = nb->bo->map;

	return err;
}

static void nouveau_unmap(struct gralloc_drm_drv_t *drv,
		struct gralloc_drm_bo_t *bo)
{
	/* The bo is implicitly unmapped at nouveau_bo_ref(NULL, bo) */
}

static void nouveau_init_kms_features(struct gralloc_drm_drv_t *drv,
		struct gralloc_drm_t *drm)
{
	struct nouveau_info *info = (struct nouveau_info *) drv;

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

static void nouveau_destroy(struct gralloc_drm_drv_t *drv)
{
	struct nouveau_info *info = (struct nouveau_info *) drv;

	nouveau_pushbuf_del(&info->pushbuf);
	nouveau_object_del(&info->channel);
	nouveau_client_del(&info->client);
	nouveau_device_del(&info->dev);
	free(info);
}

static int nouveau_init(struct nouveau_info *info)
{
	int err = 0;

	switch (info->dev->chipset & ~0xf) {
	case 0x00:
		info->arch = NV_ARCH_04;
		break;
	case 0x10:
		info->arch = NV_ARCH_10;
		break;
	case 0x20:
		info->arch = NV_ARCH_20;
		break;
	case 0x30:
		info->arch = NV_ARCH_30;
		break;
	case 0x40:
	case 0x60:
		info->arch = NV_ARCH_40;
		break;
	case 0x50:
	case 0x80:
	case 0x90:
	case 0xa0:
		info->arch = NV_TESLA;
		break;
	case 0xc0:
	case 0xd0:
		info->arch = NV_FERMI;
		break;
	case 0xe0:
	case 0xf0:
		info->arch = NV_KEPLER;
		break;
	case 0x110:
		info->arch = NV_MAXWELL;
		break;
	default:
		ALOGE("unknown nouveau chipset 0x%x", info->dev->chipset);
		err = -EINVAL;
		break;
	}

	if (info->dev->drm_version < 0x01000000 && info->dev->chipset >= 0xc0) {
		ALOGE("nouveau kernel module is too old 0x%x",
		      info->dev->drm_version);
		err = -EINVAL;
	}

	return err;
}

struct gralloc_drm_drv_t *
gralloc_drm_drv_create_for_nouveau(int fd)
{
	struct nouveau_info *info;
	struct nv04_fifo nv04_data = { .vram = 0xbeef0201, .gart = 0xbeef0202 };
	struct nvc0_fifo nvc0_data = { };
	int size, err;
	void *data;

	info = calloc(1, sizeof(*info));
	if (!info)
		return NULL;

	info->fd = fd;
	err = nouveau_device_wrap(fd, 0, &info->dev);
	if (err) {
		ALOGE("failed to wrap existing nouveau device");
		free(info);
		return NULL;
	}

	err = nouveau_init(info);
	if (err) {
		free(info);
		return NULL;
	}

	err = nouveau_client_new(info->dev, &info->client);
	if (err) {
		ALOGW("failed to create nouveau client: %d", err);
		nouveau_device_del(&info->dev);
		free(info);
		return NULL;
	}

	if (info->dev->chipset < 0xc0) {
		data = &nv04_data;
		size = sizeof(nv04_data);
	}
	else {
		data = &nvc0_data;
		size = sizeof(nvc0_data);
	}

	err = nouveau_object_new(&info->dev->object, 0,
			NOUVEAU_FIFO_CHANNEL_CLASS, data, size,
			&info->channel);

	if (err) {
		ALOGE("failed to create nouveau channel: %d", err);
		nouveau_client_del(&info->client);
		nouveau_device_del(&info->dev);
		free(info);
		return NULL;
	}

	err = nouveau_pushbuf_new(info->client, info->channel,
			4, 32 * 1024, true, &info->pushbuf);
	if (err) {
		ALOGE("failed to allocate DMA push buffer: %d", err);
		nouveau_object_del(&info->channel);
		nouveau_client_del(&info->client);
		nouveau_device_del(&info->dev);
		free(info);
		return NULL;
	}

	info->base.destroy = nouveau_destroy;
	info->base.init_kms_features = nouveau_init_kms_features;
	info->base.alloc = nouveau_alloc;
	info->base.free = nouveau_free;
	info->base.map = nouveau_map;
	info->base.unmap = nouveau_unmap;

	return &info->base;
}
