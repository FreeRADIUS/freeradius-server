#pragma once
/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * @file rlm_mruby.h
 * @brief Translates requests between the server an an mruby interpreter.
 *
 * @copyright 2016 Herwin Weststrate (freeradius@herwinw.nl)
 * @copyright 2016 The FreeRADIUS server project
 */

#ifdef HAVE_WDOCUMENTATION
DIAG_OFF(documentation)
#endif
#include <mruby.h>
#include <mruby/compile.h>
#include <mruby/array.h>
#include <mruby/hash.h>
#include <mruby/numeric.h>
#include <mruby/string.h>
#include <mruby/variable.h>
#ifdef HAVE_WDOCUMENTATION
DIAG_ON(documentation)
#endif

struct RClass *mruby_request_class(mrb_state *mrb, struct RClass *parent);
