/**
 * @file dlopen.c
 *
 * @author James Jones (jejones@networkradius.com)
 * @copyright 2020 Network RADIUS SARL (legal@networkradius.com)
 */

#include <string.h>
#include <stdio.h>
#include <dlfcn.h>
#include <gnumake.h>

#ifdef __APPLE__
#  define DL_EXTENSION ".dylib"
#else
#  include <linux/limits.h>
#  define DL_EXTENSION ".so"
#endif

static char	*mk_dlpath(char const *nm, unsigned int argc, char **argv);
static char	*mk_dlerror(char const *nm, unsigned int argc, char **argv);
int		dlopen_gmk_setup(void);
static char	*getpath(char *dl_pathname, void *handle);
extern int	plugin_is_GPL_compatible;

int plugin_is_GPL_compatible;

/** GNU make-callable function to return the absolute pathname of a dynamic library.
 * 
 * @return NULL on failure; otherwise, a string. 
 * 
 * @note argv[0] should point to the name of the library minus the extension.
 */
static char * mk_dlpath(UNUSED char const *nm, UNUSED unsigned int argc, char **argv)
{
	void	*handle;
	char	*extended_file_name;
	char	*dl_pathname;

	if (argv[0] == NULL) {
		fprintf(stderr, "file name NULL\n");
		return NULL;
	}
	
	extended_file_name = gmk_alloc(1 + strlen(DL_EXTENSION) + strlen(argv[0]));
	sprintf(extended_file_name, "%s%s", argv[0], DL_EXTENSION);

	handle = dlopen(extended_file_name, RTLD_LAZY | RTLD_LOCAL);
	if (!handle) {
		/* fprintf(stderr, "%s\n", dlerror()); */
		gmk_free(extended_file_name);
		return NULL;
	}

	dl_pathname = getpath(extended_file_name, handle);

	gmk_free(extended_file_name);
	dlclose(handle);
	return dl_pathname;
}


#ifdef __APPLE__
static char *getpath(char *extended_file_name, void *handle)
{
	// Iterate through all images currently in memory
	for (int32_t i = _dyld_image_count(); i >= 0 ; i--) {
		// dlopen() each image, check handle
		char const *image_name = _dyld_get_image_name(i);
		uv_lib_t *probe_lib = jl_load_dynamic_library(image_name, JL_RTLD_DEFAULT);
		void *probe_handle = probe_lib->handle;
		uv_dlclose(probe_lib);

		// If the handle is the same as what was passed in (modulo mode bits), return this image name
		if (((intptr_t)handle & (-4)) == ((intptr_t)probe_handle & (-4))) {
			char *dl_pathname = gmk_alloc(strlen(image_name) + 1);
			strcpy(dl_pathname, image_name);
			return dl_pathname;
		}
	}
	return NULL;
}
#else
static char *getpath(char *extended_file_name, void *handle)
{
	char	*dl_pathname = gmk_alloc(PATH_MAX);
	char	*base;

	if (dlinfo(handle, RTLD_DI_ORIGIN, dl_pathname) < 0) {
		/* fprintf(stderr, "%s\n", dlerror()); */
		gmk_free(dl_pathname);
		return NULL;
	}

	/*
	 * dlinfo() just gives the absolute path down to and including the
	 * directory the file is in, so we have to append the file name itself
	 * preceded by the '/' separator.
	 */
	base = strrchr(extended_file_name, '/');
	if (base) {
		strcat(dl_pathname, base);
	} else {
		strcat(dl_pathname, "/");
		strcat(dl_pathname, extended_file_name);
	}
	return dl_pathname;
}
#endif

static char *mk_dlerror(UNUSED char const *nm, UNUSED unsigned int argc, UNUSED char **argv)
{
	char *msg = dlerror();
	char *result;

	if (msg == NULL) return NULL;

	result = gmk_alloc(strlen(msg + 1));
	strcpy(result, msg);
	return result;
}

/** Register function(s) with make.
 * 
 * @return non-zero value on success, or zero on failure.
 * @note gmk_add_function() "returns" void, so we can't really say whether it
 *       succeeded or failed. Thus the return of the constant 1.
 */
int dlopen_gmk_setup(void)
{
	gmk_add_function("dlpath", &mk_dlpath, 1, 1, 0);
	gmk_add_function("dlerror", &mk_dlerror, 0, 0, 0);
	return 1;
}
