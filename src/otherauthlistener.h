/*
 * Copyright (C) 2015 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#pragma once

#include <polkit/polkit.h>
#define POLKIT_AGENT_I_KNOW_API_IS_SUBJECT_TO_CHANGE
#include <polkitagent/polkitagent.h>

G_BEGIN_DECLS

#define OTHERAUTH_TYPE_LISTENER          (otherauth_listener_get_type())
#define OTHERAUTH_LISTENER(o)            (G_TYPE_CHECK_INSTANCE_CAST ((o), OTHERAUTH_TYPE_LISTENER, OtherauthListener))
#define OTHERAUTH_IS_LISTENER(o)         (G_TYPE_CHECK_INSTANCE_TYPE ((o), OTHERAUTH_TYPE_LISTENER))

typedef struct _OtherauthListener OtherauthListener;

GType                otherauth_listener_get_type (void) G_GNUC_CONST;
OtherauthListener   *otherauth_listener_new      (GCancellable   *cancellable,
                                                  GError        **error);


G_END_DECLS
