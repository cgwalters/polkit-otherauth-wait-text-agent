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

#include <stdio.h>
#include <polkit/polkit.h>
#define POLKIT_AGENT_I_KNOW_API_IS_SUBJECT_TO_CHANGE
#include <polkitagent/polkitagent.h>

#include "otherauthlistener.h"

struct App {
  gboolean running;
  GError **error;
};

static void
on_child_exited (GPid  pid,
                 gint  status,
                 gpointer user_data)
{
  struct App *app = user_data;

  (void) g_spawn_check_exit_status (status, app->error);
  
  app->running = FALSE;
  g_main_context_wakeup (NULL);
}

int
main (int argc, char *argv[])
{
  gchar *opt_process = NULL;
  gchar *opt_system_bus_name = NULL;
  PolkitAuthority *authority = NULL;
  PolkitSubject *subject = NULL;
  gpointer local_agent_handle = NULL;
  PolkitAgentListener *listener = NULL;
  GVariant *listener_options = NULL;
  GError *local_error = NULL;
  GError **error = &local_error;
  struct App appdata = { 0, };
  struct App *app = &appdata;
  int ret;
  pid_t child;

  {
    GPtrArray *new_argv = g_ptr_array_new ();
    guint i;
    for (i = 1; i < argc; i++)
      g_ptr_array_add (new_argv, argv[i]);
    g_ptr_array_add (new_argv, NULL);
    if (!g_spawn_async (NULL, (char**)new_argv->pdata, NULL,
                        G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_SEARCH_PATH, NULL, NULL,
                        &child,
                        error))
      goto out;
    g_ptr_array_unref (new_argv);
  }

  subject = polkit_unix_process_new_for_owner (getpid (),
                                               0, /* 0 means "look up start-time in /proc" */
                                               getuid ());

  authority = polkit_authority_get_sync (NULL /* GCancellable* */, error);
  if (authority == NULL)
    goto out;

  /* this will fail if we can't find a controlling terminal */
  listener = (PolkitAgentListener*)otherauth_listener_new (NULL, error);
  if (listener == NULL)
    goto out;

  local_agent_handle = polkit_agent_listener_register_with_options (listener,
                                                                    POLKIT_AGENT_REGISTER_FLAGS_RUN_IN_THREAD,
                                                                    subject,
                                                                    NULL, /* object_path */
                                                                    listener_options,
                                                                    NULL, /* GCancellable */
                                                                    error);
  listener_options = NULL; /* consumed */
  g_object_unref (listener);
  if (local_agent_handle == NULL)
    goto out;

  g_child_watch_add (child, on_child_exited, app);

  app->running = TRUE;
  app->error = error;
  while (app->running)
    g_main_context_iteration (NULL, TRUE);

  ret = 0;
 out:
  if (local_error)
    {
      g_printerr ("%s\n", local_error->message);
      g_error_free (local_error);
      ret = 1;
    }

  if (local_agent_handle != NULL)
    polkit_agent_listener_unregister (local_agent_handle);

  if (listener_options != NULL)
    g_variant_unref (listener_options);

  if (subject != NULL)
    g_object_unref (subject);

  if (authority != NULL)
    g_object_unref (authority);

  g_free (opt_process);
  g_free (opt_system_bus_name);

  return ret;
}
