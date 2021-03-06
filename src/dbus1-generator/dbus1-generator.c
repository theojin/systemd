/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "alloc-util.h"
#include "bus-internal.h"
#include "bus-util.h"
#include "cgroup-util.h"
#include "conf-parser.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "mkdir.h"
#include "special.h"
#include "unit-name.h"
#include "util.h"

static const char *arg_dest_late = "/tmp", *arg_dest = "/tmp";

static int create_dbus_files(
                const char *path,
                const char *name,
                const char *service,
                const char *exec,
                const char *user,
                const char *type) {

        _cleanup_free_ char *b = NULL, *s = NULL, *lnk = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(path);
        assert(name);
        assert(service || exec);

        if (!service) {
                _cleanup_free_ char *a = NULL;

                s = strjoin("dbus-", name, ".service", NULL);
                if (!s)
                        return log_oom();

                a = strjoin(arg_dest_late, "/", s, NULL);
                if (!a)
                        return log_oom();

                f = fopen(a, "wxe");
                if (!f)
                        return log_error_errno(errno, "Failed to create %s: %m", a);

                fprintf(f,
                        "# Automatically generated by systemd-dbus1-generator\n\n"
                        "[Unit]\n"
                        "SourcePath=%s\n"
                        "Description=DBUS1: %s\n"
                        "Documentation=man:systemd-dbus1-generator(8)\n\n"
                        "[Service]\n"
                        "ExecStart=%s\n"
                        "Type=dbus\n"
                        "BusName=%s\n",
                        path,
                        name,
                        exec,
                        name);

                if (user)
                        fprintf(f, "User=%s\n", user);


                if (type) {
                        fprintf(f, "Environment=DBUS_STARTER_BUS_TYPE=%s\n", type);

                        if (streq(type, "system"))
                                fprintf(f, "Environment=DBUS_STARTER_ADDRESS=" DEFAULT_SYSTEM_BUS_ADDRESS "\n");
                        else if (streq(type, "session")) {
                                char *run;

                                run = getenv("XDG_RUNTIME_DIR");
                                if (!run) {
                                        log_error("XDG_RUNTIME_DIR not set.");
                                        return -EINVAL;
                                }

                                fprintf(f, "Environment=DBUS_STARTER_ADDRESS="KERNEL_USER_BUS_ADDRESS_FMT ";" UNIX_USER_BUS_ADDRESS_FMT "\n",
                                        getuid(), run);
                        }
                }

                r = fflush_and_check(f);
                if (r < 0)
                        return log_error_errno(r, "Failed to write %s: %m", a);

                f = safe_fclose(f);

                service = s;
        }

        b = strjoin(arg_dest_late, "/", name, ".busname", NULL);
        if (!b)
                return log_oom();

        f = fopen(b, "wxe");
        if (!f)
                return log_error_errno(errno, "Failed to create %s: %m", b);

        fprintf(f,
                "# Automatically generated by systemd-dbus1-generator\n\n"
                "[Unit]\n"
                "SourcePath=%s\n"
                "Description=DBUS1: %s\n"
                "Documentation=man:systemd-dbus1-generator(8)\n\n"
                "[BusName]\n"
                "Name=%s\n"
                "Service=%s\n"
                "AllowWorld=talk\n",
                path,
                name,
                name,
                service);

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to write %s: %m", b);

        lnk = strjoin(arg_dest_late, "/" SPECIAL_BUSNAMES_TARGET ".wants/", name, ".busname", NULL);
        if (!lnk)
                return log_oom();

        mkdir_parents_label(lnk, 0755);
        if (symlink(b, lnk))
                return log_error_errno(errno, "Failed to create symlink %s: %m", lnk);

        return 0;
}

static int add_dbus(const char *path, const char *fname, const char *type) {
        _cleanup_free_ char *name = NULL, *exec = NULL, *user = NULL, *service = NULL;

        const ConfigTableItem table[] = {
                { "D-BUS Service", "Name", config_parse_string, 0, &name },
                { "D-BUS Service", "Exec", config_parse_string, 0, &exec },
                { "D-BUS Service", "User", config_parse_string, 0, &user },
                { "D-BUS Service", "SystemdService", config_parse_string, 0, &service },
                { },
        };

        char *p;
        int r;

        assert(path);
        assert(fname);

        p = strjoina(path, "/", fname);
        r = config_parse(NULL, p, NULL,
                         "D-BUS Service\0",
                         config_item_table_lookup, table,
                         true, false, true, NULL);
        if (r < 0)
                return r;

        if (!name) {
                log_warning("Activation file %s lacks name setting, ignoring.", p);
                return 0;
        }

        if (!service_name_is_valid(name)) {
                log_warning("Bus service name %s is not valid, ignoring.", name);
                return 0;
        }

        if (streq(name, "org.freedesktop.systemd1")) {
                log_debug("Skipping %s, identified as systemd.", p);
                return 0;
        }

        if (service) {
                if (!unit_name_is_valid(service, UNIT_NAME_PLAIN|UNIT_NAME_INSTANCE)) {
                        log_warning("Unit name %s is not valid, ignoring.", service);
                        return 0;
                }
                if (!endswith(service, ".service")) {
                        log_warning("Bus names can only activate services, ignoring %s.", p);
                        return 0;
                }
        } else {
                if (streq(exec, "/bin/false") || !exec) {
                        log_warning("Neither service name nor binary path specified, ignoring %s.", p);
                        return 0;
                }

                if (exec[0] != '/') {
                        log_warning("Exec= in %s does not start with an absolute path, ignoring.", p);
                        return 0;
                }
        }

        return create_dbus_files(p, name, service, exec, user, type);
}

static int parse_dbus_fragments(const char *path, const char *type) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        int r;

        assert(path);
        assert(type);

        d = opendir(path);
        if (!d) {
                if (errno == -ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to enumerate D-Bus activated services: %m");
        }

        r = 0;
        FOREACH_DIRENT(de, d, goto fail) {
                int q;

                if (!endswith(de->d_name, ".service"))
                        continue;

                q = add_dbus(path, de->d_name, type);
                if (q < 0)
                        r = q;
        }

        return r;

fail:
        return log_error_errno(errno, "Failed to read D-Bus services directory: %m");
}

static int link_busnames_target(const char *units) {
        const char *f, *t;

        f = strjoina(units, "/" SPECIAL_BUSNAMES_TARGET);
        t = strjoina(arg_dest, "/" SPECIAL_BASIC_TARGET ".wants/" SPECIAL_BUSNAMES_TARGET);

        mkdir_parents_label(t, 0755);
        if (symlink(f, t) < 0)
                return log_error_errno(errno, "Failed to create symlink %s: %m", t);

        return 0;
}

static int create_compatibility(const char *units, const char *type) {
        const char *t;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        t = strjoina(arg_dest, "/" SPECIAL_DBUS_SERVICE);
        if (!t)
                return log_oom();

        f = fopen(t, "wxe");
        if (!f)
                return log_error_errno(errno, "Failed to create %s: %m", t);

        fprintf(f,
                "# Automatically generated by systemd-dbus1-generator\n\n"
                "[Unit]\n"
                "Description=DBUS1: dbus.service for kdbus compatibility\n"
                "[Service]\n"
                "ExecStart=/bin/true\n"
                "RemainAfterExit=true\n");

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to write %s: %m", t);

        f = safe_fclose(f);


        t = strjoina(arg_dest, "/" SPECIAL_DBUS_SOCKET);
        if (!t)
                return log_oom();

        f = fopen(t, "wxe");
        if (!f)
                return log_error_errno(errno, "Failed to create %s: %m", t);

        fprintf(f,
                "# Automatically generated by systemd-dbus1-generator\n\n"
                "[Unit]\n"
                "Description=DBUS1: dbus.socket for kdbus compatibility\n"
                "[Socket]\n"
                "SmackLabelIPIn=^\n"
                "ListenStream=@/tmp/.kdbus_bus_%s_%d\n", type, getuid());


        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to write %s: %m", t);

        f = safe_fclose(f);

        return 0;
}

int main(int argc, char *argv[]) {
        const char *path, *type, *units;
        int r, q;

        if (argc > 1 && argc != 4) {
                log_error("This program takes three or no arguments.");
                return EXIT_FAILURE;
        }

        if (argc > 1) {
                arg_dest = argv[1];
                arg_dest_late = argv[3];
        }

        log_set_target(LOG_TARGET_SAFE);
        log_parse_environment();
        log_open();

        umask(0022);

        if (!is_kdbus_available())
                return 0;

        r = cg_pid_get_owner_uid(0, NULL);
        if (r >= 0) {
                path = "/usr/share/dbus-1/services";
                type = "session";
                units = USER_DATA_UNIT_PATH;
        } else if (r == -ENXIO) {
                path = "/usr/share/dbus-1/system-services";
                type = "system";
                units = SYSTEM_DATA_UNIT_PATH;
        } else
                return log_error_errno(r, "Failed to determine whether we are running as user or system instance: %m");

        r = parse_dbus_fragments(path, type);

        /* FIXME: One day this should just be pulled in statically from basic.target */
        q = link_busnames_target(units);
        if (q < 0)
                r = q;

        q = create_compatibility(units, type);
        if (q < 0)
                r = q;

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
