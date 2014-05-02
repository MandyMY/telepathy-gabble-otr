/*
 * Copyright (C) 2014 Collabora Ltd.
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

#ifndef __GABBLE_IM_CHANNEL_OTR_H__
#define __GABBLE_IM_CHANNEL_OTR_H__

#include "im-channel.h"

G_BEGIN_DECLS

void gabble_im_channel_otr_init (GabbleIMChannel *self);

gboolean gabble_im_channel_otr_sending (GabbleIMChannel *self,
    WockyStanza *stanza,
    GError **error);

gchar *gabble_im_channel_otr_receiving (GabbleIMChannel *self,
    const gchar *content);

G_END_DECLS

#endif
