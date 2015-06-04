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

#include "config.h"

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>

#include <termios.h>
#include <unistd.h>

#include "otherauthlistener.h"

/**
 * SECTION:polkitagenttextlistener
 * @title: OtherauthListener
 * @short_description: Text-based Authentication Agent
 * @stability: Unstable
 *
 * #OtherauthListener is an #PolkitAgentListener implementation
 * that interacts with the user using a textual interface.
 */

/**
 * OtherauthListener:
 *
 * The #OtherauthListener struct should not be accessed directly.
 */
struct _OtherauthListener
{
  PolkitAgentListener parent_instance;

  GSimpleAsyncResult *simple;
  gulong cancel_id;
  GCancellable *cancellable;

  FILE *tty;
};

typedef struct
{
  PolkitAgentListenerClass parent_class;
} OtherauthListenerClass;

static void otherauth_listener_initiate_authentication (PolkitAgentListener  *_listener,
                                                                const gchar          *action_id,
                                                                const gchar          *message,
                                                                const gchar          *icon_name,
                                                                PolkitDetails        *details,
                                                                const gchar          *cookie,
                                                                GList                *identities,
                                                                GCancellable         *cancellable,
                                                                GAsyncReadyCallback   callback,
                                                                gpointer              user_data);

static gboolean otherauth_listener_initiate_authentication_finish (PolkitAgentListener  *_listener,
                                                                           GAsyncResult         *res,
                                                                           GError              **error);

static void initable_iface_init (GInitableIface *initable_iface);

G_DEFINE_TYPE_WITH_CODE (OtherauthListener, otherauth_listener, POLKIT_AGENT_TYPE_LISTENER,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, initable_iface_init));

static void
otherauth_listener_init (OtherauthListener *listener)
{
}

static void
otherauth_listener_finalize (GObject *object)
{
  OtherauthListener *listener = OTHERAUTH_LISTENER (object);

  if (listener->tty != NULL)
    fclose (listener->tty);

  if (G_OBJECT_CLASS (otherauth_listener_parent_class)->finalize != NULL)
    G_OBJECT_CLASS (otherauth_listener_parent_class)->finalize (object);
}

static void
otherauth_listener_class_init (OtherauthListenerClass *klass)
{
  GObjectClass *gobject_class;
  PolkitAgentListenerClass *listener_class;

  gobject_class = G_OBJECT_CLASS (klass);
  gobject_class->finalize = otherauth_listener_finalize;

  listener_class = POLKIT_AGENT_LISTENER_CLASS (klass);
  listener_class->initiate_authentication        = otherauth_listener_initiate_authentication;
  listener_class->initiate_authentication_finish = otherauth_listener_initiate_authentication_finish;
}

OtherauthListener *
otherauth_listener_new (GCancellable  *cancellable,
                        GError       **error)
{
  g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);
  return g_initable_new (OTHERAUTH_TYPE_LISTENER,
                         cancellable,
                         error,
                         NULL);
}

/* ---------------------------------------------------------------------------------------------------- */

static gboolean
initable_init (GInitable     *initable,
               GCancellable  *cancellable,
               GError       **error)
{
  OtherauthListener *listener = OTHERAUTH_LISTENER (initable);
  gboolean ret;
  const gchar *tty_name;

  ret = FALSE;

  tty_name = ctermid (NULL);
  if (tty_name == NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Cannot determine pathname for current controlling terminal for the process: %s",
                   strerror (errno));
      goto out;
    }

  listener->tty = fopen (tty_name, "r+");
  if (listener->tty == NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Error opening current controlling terminal for the process (`%s'): %s",
                   tty_name,
                   strerror (errno));
      goto out;
    }

  ret = TRUE;

 out:
  return ret;
}

static void
initable_iface_init (GInitableIface *initable_iface)
{
  initable_iface->init = initable_init;
}

/* ---------------------------------------------------------------------------------------------------- */

static gchar *
identity_to_human_readable_string (PolkitIdentity *identity)
{
  gchar *ret;

  g_return_val_if_fail (POLKIT_IS_IDENTITY (identity), NULL);

  ret = NULL;
  if (POLKIT_IS_UNIX_USER (identity))
    {
      struct passwd pw;
      struct passwd *ppw;
      char buf[2048];
      int res;

      res = getpwuid_r (polkit_unix_user_get_uid (POLKIT_UNIX_USER (identity)),
                        &pw,
                        buf,
                        sizeof buf,
                        &ppw);
      if (res != 0)
        {
          g_warning ("Error calling getpwuid_r: %s", strerror (res));
        }
      else
        {
          if (ppw->pw_gecos == NULL || strlen (ppw->pw_gecos) == 0 || strcmp (ppw->pw_gecos, ppw->pw_name) == 0)
            {
              ret = g_strdup_printf ("%s", ppw->pw_name);
            }
          else
            {
              ret = g_strdup_printf ("%s (%s)", ppw->pw_gecos, ppw->pw_name);
            }
        }
    }
  if (ret == NULL)
    ret = polkit_identity_to_string (identity);
  return ret;
}

static PolkitIdentity *
choose_identity (OtherauthListener *listener,
                 GList                   *identities)
{
  GList *l;
  guint n;
  guint num_identities;
  GString *str;
  PolkitIdentity *ret;
  guint num;
  gchar *endp;

  ret = NULL;

  fprintf (listener->tty, "Multiple identities can be used for authentication:\n");
  for (l = identities, n = 0; l != NULL; l = l->next, n++)
    {
      PolkitIdentity *identity = POLKIT_IDENTITY (l->data);
      gchar *s;
      s = identity_to_human_readable_string (identity);
      fprintf (listener->tty, " %d.  %s\n", n + 1, s);
      g_free (s);
    }
  num_identities = n;
  fprintf (listener->tty, "Choose identity to authenticate as (1-%d): ", num_identities);
  fflush (listener->tty);

  str = g_string_new (NULL);
  while (TRUE)
    {
      gint c;
      c = getc (listener->tty);
      if (c == '\n')
        {
          /* ok, done */
          break;
        }
      else if (c == EOF)
        {
          g_error ("Got unexpected EOF while reading from controlling terminal.");
          abort ();
          break;
        }
      else
        {
          g_string_append_c (str, c);
        }
    }

  num = strtol (str->str, &endp, 10);
  if (str->len == 0 || *endp != '\0' || (num < 1 || num > num_identities))
    {
      fprintf (listener->tty, "Invalid response `%s'.\n", str->str);
      goto out;
    }

  ret = g_list_nth_data (identities, num-1);

 out:
  g_string_free (str, TRUE);
  return ret;
}


static void
otherauth_listener_initiate_authentication (PolkitAgentListener  *_listener,
                                                    const gchar          *action_id,
                                                    const gchar          *message,
                                                    const gchar          *icon_name,
                                                    PolkitDetails        *details,
                                                    const gchar          *cookie,
                                                    GList                *identities,
                                                    GCancellable         *cancellable,
                                                    GAsyncReadyCallback   callback,
                                                    gpointer              user_data)
{
  OtherauthListener *listener = OTHERAUTH_LISTENER (_listener);
  GSimpleAsyncResult *simple;
  PolkitIdentity *identity;
  char *line = NULL;
  ssize_t r;
  size_t n;

  simple = g_simple_async_result_new (G_OBJECT (listener),
                                      callback,
                                      user_data,
                                      otherauth_listener_initiate_authentication);

  g_assert (g_list_length (identities) >= 1);

  fprintf (listener->tty, "\x1B[1;31m");
  fprintf (listener->tty,
           "(not really) AUTHENTICATING: %s \n",
           action_id);
  fprintf (listener->tty, "\x1B[0m");
  fprintf (listener->tty,
           "%s\n",
           message);

  /* handle multiple identies by asking which one to use */
  if (g_list_length (identities) > 1)
    {
      identity = choose_identity (listener, identities);
      if (identity == NULL)
        {
          fprintf (listener->tty, "\x1B[1;31m");
          fprintf (listener->tty, "==== AUTHENTICATION CANCELED ===\n");
          fprintf (listener->tty, "\x1B[0m");
          fflush (listener->tty);
          g_simple_async_result_set_error (simple,
                                           POLKIT_ERROR,
                                           POLKIT_ERROR_FAILED,
                                           "Authentication was canceled.");
          g_simple_async_result_complete_in_idle (simple);
          g_object_unref (simple);
          goto out;
        }
    }
  else
    {
      gchar *s;
      identity = identities->data;
      s = identity_to_human_readable_string (identity);
      fprintf (listener->tty,
               "Authenticating as: %s\n",
               s);
      g_free (s);
    }

  fprintf (listener->tty, "COOKIE: %s\nPress Return to see if you won the authentication race!\n",
           cookie);
  r = getline (&line, &n, stdin);
  if (r < 0)
    {
      perror ("getline");
    }
  free (line);

  g_simple_async_result_complete_in_idle (simple);
  g_object_unref (simple);

 out:
  ;
}

static gboolean
otherauth_listener_initiate_authentication_finish (PolkitAgentListener  *_listener,
                                                           GAsyncResult         *res,
                                                           GError              **error)
{
  gboolean ret;

  g_warn_if_fail (g_simple_async_result_get_source_tag (G_SIMPLE_ASYNC_RESULT (res)) ==
                  otherauth_listener_initiate_authentication);

  ret = FALSE;

  if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (res), error))
    goto out;

  ret = TRUE;

 out:
  return ret;
}
