/*
 * tp-handle.h - Header for basic Telepathy-GLib handle functionality
 *
 * Copyright (C) 2005, 2007 Collabora Ltd.
 * Copyright (C) 2005, 2007 Nokia Corporation
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef __TP_HANDLE_H__
#define __TP_HANDLE_H__

#include <glib.h>
#include <telepathy-glib/enums.h>
#include <telepathy-glib/errors.h>

G_BEGIN_DECLS

/**
 * TpHandle:
 *
 * Type representing Telepathy handles within telepathy-glib
 */
typedef guint32 TpHandle;

/* Must be static inline because it references NUM_TP_HANDLE_TYPES -
 * if it wasn't inlined, a newer libtelepathy-glib with a larger number
 * of handle types might accept handle types that won't fit in the
 * connection manager's array of length NUM_TP_HANDLE_TYPES
 */
/**
 * tp_handle_type_is_valid:
 * @type: A handle type to be checked
 * @error: Error indicator to be set if the handle type is invalid
 *
 * If the given handle type is valid, return TRUE. If not, set the GError
 * and return FALSE.
 *
 * Returns: TRUE if the handle type is valid.
 */
static inline gboolean
tp_handle_type_is_valid (TpHandleType type, GError **error)
{
  if (type > TP_HANDLE_TYPE_NONE && type < NUM_TP_HANDLE_TYPES)
    return TRUE;

  tp_g_set_error_invalid_handle_type (type, error);
  return FALSE;
}

G_END_DECLS

#endif
