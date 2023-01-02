/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
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
 * $Id$
 *
 * @file src/radius.c
 * @brief Python bindings for major FreeRADIUS libraries
 *
 * @copyright Network RADIUS SAS(legal@networkradius.com)
 * @author 2023 Jorge Pereira (jpereira@freeradius.org)
 */

RCSID("$Id$")

#include "src/pyfr.h"
#include "src/radius.h"

#include <freeradius-devel/util/pair_legacy.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/protocol/radius/freeradius.internal.h>

extern fr_dict_t const *dict_freeradius;
extern fr_dict_t const *dict_radius;

PyObject *pyfr_ErrorRadius = NULL;

PYFR_INTERNAL int pyfr_radius_init(UNUSED PyObject *self, UNUSED PyObject *args, UNUSED PyObject *kwds)
{
    pyfr_mod_state_t  *state = pyfr_get_mod_state();

    if (state->radius_loaded) return 0;

    DEBUG3("Initialising libfreeradius-radius");

    if (fr_radius_init() < 0) {
        PyErr_Format(pyfr_ErrorRadius, "fr_radius_init() Failed: %s", fr_strerror());
        goto error;
    }

    state->radius_loaded = true;

    return 0;

error:
    return -1;
}

PYFR_INTERNAL PyObject *pyfr_radius_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    const char * const keywords[] = { "auth_host", "auth_port", NULL};
    char const *auth_host = NULL, *auth_port = NULL;
    pyfr_radius_ctx_t *ctx;
    
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|ss", UNCONST(char **, keywords), &auth_host, &auth_port)) return NULL;

    if (!auth_host) auth_host = "127.0.0.1";
    if (!auth_port) auth_port = "1812";

    ctx = PyObject_New(pyfr_radius_ctx_t, type);
    ctx->auth_host = talloc_strdup(NULL, auth_host);
    ctx->auth_port = talloc_strdup(NULL, auth_port);

    return (PyObject *)ctx;
}

PYFR_INTERNAL void pyfr_radius_dealloc(PyObject *self)
{
    pyfr_radius_ctx_t *ctx = (pyfr_radius_ctx_t *)self;

    fr_radius_free();

    TALLOC_FREE(ctx->auth_host);
    TALLOC_FREE(ctx->auth_port);

    PyObject_Del(ctx);
}

static void *pyfr_radius_next_encodable(fr_dlist_head_t *list, void *current, void *uctx)
{
    fr_pair_t *vp = current;
    fr_dict_t *dict = talloc_get_type_abort(uctx, fr_dict_t);

    while ((vp = fr_dlist_next(list, vp))) {
        PAIR_VERIFY(vp);
        if ((vp->da->dict == dict) &&
            (!vp->da->flags.internal || ((vp->da->attr > FR_TAG_BASE) && (vp->da->attr < (FR_TAG_BASE + 0x20))))) {
            break;
        }
    }

    return vp;
}

PYFR_INTERNAL PyObject *pyfr_radius_encode_pair(UNUSED PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    const char * const keywords[] = { "attrs", "secret", NULL};
    PyObject         *data = NULL, *kattrs, *key, *value_list;
    Py_ssize_t       pos = 0;
    fr_pair_t        *vp;
    fr_pair_list_t   tmp_list;
    fr_dict_t const  *dict = dict_radius;
    fr_dcursor_t     cursor;
    fr_dbuff_t       work_dbuff;
    char             buff[MAX_PACKET_LEN];
    char             *ksecret, *secret = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "Os", UNCONST(char **, keywords), &kattrs, &ksecret)) {
        PyErr_SetString(pyfr_ErrorRadius, "Invalid Argument. e.g: attrs={ \"attribute1\": [ \"arg1\" ], \"attribute2\": [ \"arg2\" , ... ] }");
        return NULL;
    }

    fr_pair_list_init(&tmp_list);

    /*
     * Walk through the Radius.encode_pair(..., attrs={ "attrs": [ "arg" ], ... }, ...)
     * parameters and build VPs list
     */
    while (PyDict_Next(kattrs, &pos, &key, &value_list)) {
        if (!PyList_Check(value_list)) {
            PyErr_Format(pyfr_ErrorRadius, "Wrong argument at position %ld, it must be a 'list'. e.g: attrs={\"attribute\": [ \"arg1\", ... ] }", pos);
            goto error;
        }

        for (int i = 0; i < PyList_Size(value_list); i++) {
            char const *lhs, *rhs;
            char *lhs_rhs;

            lhs = PyUnicode_AsUTF8(key);
            rhs = PyUnicode_AsUTF8(PyList_GetItem(value_list, i));
            lhs_rhs = talloc_asprintf(NULL, "%s=\"%s\"", lhs, rhs);

            DEBUG2("Encode %s", lhs_rhs);

            if (fr_pair_list_afrom_str(NULL, fr_dict_root(dict_radius), lhs_rhs, strlen(lhs_rhs), &tmp_list) != T_EOL) {
                pyfr_ErrorObject_as_strerror(pyfr_ErrorRadius);
                talloc_free(lhs_rhs);
                goto error;
            }

            talloc_free(lhs_rhs);
        }
    }

    /*
     *  Output may be an error, and we return it if so.
     */
    if (fr_pair_list_empty(&tmp_list)) {
        PyErr_SetString(pyfr_ErrorRadius, "Empty avp list.");
        goto error;
    }

    fr_dbuff_init(&work_dbuff, buff, sizeof(buff));

    /* fr_radius_encode_pair() expects talloced 'secret' parameter */
    secret = talloc_strdup(NULL, ksecret);

    /*
     *  Loop over the reply attributes for the packet.
     */
    fr_pair_dcursor_iter_init(&cursor, &tmp_list, pyfr_radius_next_encodable, dict);
    while ((vp = fr_dcursor_current(&cursor))) {
        PAIR_VERIFY(vp);

        DEBUG3("Calling fr_radius_encode_pair() for %pP (%s).", vp, fr_type_to_str(vp->da->type));

        /*
         *  Encode an individual VP
         */
        if (fr_radius_encode_pair(&work_dbuff, &cursor, &(fr_radius_ctx_t){ .secret = secret }) < 0) {
            pyfr_ErrorObject_as_strerror(pyfr_ErrorRadius);
            goto error;
        }
    }

    FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), fr_dbuff_used(&work_dbuff), "%s encoded packet", __FUNCTION__);

    data = Py_BuildValue("y#", fr_dbuff_start(&work_dbuff),fr_dbuff_used(&work_dbuff));
    if (!data) {
        PyErr_SetString(pyfr_ErrorRadius, "Py_BuildValue() failed.");
        goto error;
    }

error:
    TALLOC_FREE(secret);

    /* clean up and return result */
    fr_pair_list_free(&tmp_list);

    return data;
}

PYFR_INTERNAL PyObject *pyfr_radius_decode_pair(UNUSED PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    PyObject           *attrs = NULL;
    fr_pair_t          *vp;
    fr_pair_list_t     tmp_list;
    fr_dcursor_t       cursor;
    const char * const keywords[] = { "data", "secret", NULL};
    char               *ksecret;
    uint8_t            *kdata, *ptr;
    size_t             kdata_len, ptr_len, my_len;
    pyfr_mod_state_t   *state = pyfr_get_mod_state();

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "y#s", UNCONST(char **, keywords), &kdata, &kdata_len, &ksecret)) {
        PyErr_SetString(pyfr_ErrorRadius, "Invalid parameter, expecting packet payload.");
        return NULL;
    }

    FR_PROTO_HEX_DUMP(kdata, kdata_len, "%s decode packet", __FUNCTION__);

    ptr     = kdata;
    ptr_len = kdata_len;

    fr_pair_list_init(&tmp_list);

    /*
     *  Loop over the attributes, decoding them into VPs.
     */
    while (ptr_len > 0) {
        my_len = fr_radius_decode_pair(state->autofree, &tmp_list, ptr, ptr_len, &(fr_radius_ctx_t){ .secret = ksecret, .end = (kdata + kdata_len) });
        if (my_len < 0) {
            PyErr_Format(pyfr_ErrorRadius, "fr_radius_decode_pair() returned %ld. (%s)", my_len, fr_strerror());
            goto error;
        }

        /*
        *  If my_len is larger than the room in the packet,
        *  all kinds of bad things happen.
        */
        if (!fr_cond_assert(my_len <= ptr_len)) goto error;

        ptr += my_len;
        ptr_len -= my_len;
    }

    if (fr_pair_list_num_elements(&tmp_list) < 1) {
        PyErr_SetString(pyfr_ErrorRadius, "Failed decoding packet");
        goto error;
    }

    attrs = PyDict_New();
    for (vp = fr_pair_dcursor_init(&cursor, &tmp_list);
         vp;
         vp = fr_dcursor_next(&cursor)) {
        PyObject *value_list;
        char lhs[64], rhs[128];

        PAIR_VERIFY(vp);

        DEBUG3("Decoding %pP", vp);

        fr_dict_attr_oid_print(&FR_SBUFF_OUT(lhs, sizeof(lhs)), NULL, vp->da, false);
        fr_pair_print_value_quoted(&FR_SBUFF_OUT(rhs, sizeof(rhs)), vp, T_BARE_WORD);

        /* the RHS already exists? then, append it */
        value_list = PyDict_GetItemString(attrs, lhs);
        if (!value_list) value_list = PyList_New(0);

        PyList_Append(value_list, PyUnicode_FromString(rhs));
        PyDict_SetItemString(attrs, lhs, value_list);
    }

error:
    /* clean up and return result */
    fr_pair_list_free(&tmp_list);

    return attrs;
}

PYFR_INTERNAL PyObject *pyfr_radius_encode_packet(UNUSED PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    const char * const keywords[] = { "attrs", "id", "secret", NULL};
    uint8_t            kpacket_id = 0;
    char               *ksecret = NULL, *secret = NULL;
    Py_ssize_t         pos = 0, i =0;
    PyObject           *data = NULL, *kattrs, *key, *value_list;
    fr_pair_t          *vp;
    fr_pair_list_t     tmp_list;
    uint8_t            buff[MAX_PACKET_LEN];
    ssize_t            slen;
    char               *lhs_rhs;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OBs", UNCONST(char **, keywords), &kattrs, &kpacket_id, &ksecret)) return NULL;

    fr_pair_list_init(&tmp_list);

    /*
     * Walk through the Radius.encode_packet(..., attrs={ "attrs": [ "arg" ], ... }, ...)
     * parameters and build VPs list
     */
    while (PyDict_Next(kattrs, &pos, &key, &value_list)) {
        if (!PyList_Check(value_list)) {
            PyErr_SetString(pyfr_ErrorRadius, "Wrong argument, it must be a 'list'. e.g: \"attribute\": [ \"arg1\", ... ]");
            goto error;
        }

        for (i = 0; i < PyList_Size(value_list); i++) {
            char const *lhs, *rhs;
            
            lhs = PyUnicode_AsUTF8(key);
            rhs = PyUnicode_AsUTF8(PyList_GetItem(value_list, i));
            lhs_rhs = talloc_asprintf(NULL, "%s=\"%s\"", lhs, rhs);

            DEBUG2("Encode %s", lhs_rhs);

            if (fr_pair_list_afrom_str(NULL, fr_dict_root(dict_radius), lhs_rhs, strlen(lhs_rhs), &tmp_list) != T_EOL) {
                pyfr_ErrorObject_as_strerror(pyfr_ErrorRadius);
                talloc_free(lhs_rhs);
                goto error;
            }

            talloc_free(lhs_rhs);
        }
    }

    /*
     *  Output may be an error, and we return it if so.
     */
    if (fr_pair_list_empty(&tmp_list)) {
        PyErr_SetString(pyfr_ErrorRadius, "Empty avp list");
        goto error;
    }

    /* We can't go without Packet-Type */
    vp = fr_pair_find_by_child_num(&tmp_list, NULL, fr_dict_root(dict_radius), FR_PACKET_TYPE);
    if (!vp) {
        PyErr_SetString(pyfr_ErrorRadius, "We can not go without 'Packet-Type' attribute.");
        goto error;
    }

    /* fr_radius_encode_pair() expects talloced 'secret' parameter */
    secret = talloc_strdup(NULL, ksecret);

    slen = fr_radius_encode(buff, sizeof(buff), NULL, secret, strlen(secret), vp->vp_uint32, kpacket_id, &tmp_list);
    if (slen < 0) {
        pyfr_ErrorObject_as_strerror(pyfr_ErrorRadius);
        goto error;
    }

    FR_PROTO_HEX_DUMP(buff, slen, "%s encoded data", __FUNCTION__);

    data = Py_BuildValue("y#", buff, slen);
    if (!data) {
        PyErr_SetString(pyfr_ErrorRadius, "Py_BuildValue() failed.");
        goto error;
    }

error:
    /* clean up and return result */

    TALLOC_FREE(secret);

    fr_pair_list_free(&tmp_list);
    return data;
}

PYFR_INTERNAL PyObject *pyfr_radius_decode_packet(UNUSED PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    PyObject           *ret = NULL, *attrs;
    fr_pair_t          *vp;
    fr_pair_list_t     tmp_list;
    fr_dcursor_t       cursor;
    const char * const keywords[] = { "data", "secret", NULL};
    char               *ksecret, *secret;
    uint8_t const      *kdata;
    size_t             kdata_len;
    uint8_t            packet_id = 0;
    pyfr_mod_state_t   *state = pyfr_get_mod_state();

    /* get one argument as an iterator */
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "y#s", UNCONST(char **, keywords), &kdata, &kdata_len, &ksecret)) return NULL;

    FR_PROTO_HEX_DUMP(kdata, kdata_len, "%s decode packet", __FUNCTION__);

    fr_pair_list_init(&tmp_list);

    secret = talloc_strdup(NULL, ksecret); /* Internally the fr_radius_decode_tunnel_password() expects a talloc's secret string. */
    if (fr_radius_decode(state->autofree, &tmp_list, kdata, kdata_len, NULL, secret, talloc_array_length(secret) - 1) < 0) {
        PyErr_SetString(pyfr_ErrorRadius, "Failed decoding packet");
        goto error;
    }

    if (fr_pair_list_num_elements(&tmp_list) < 1) {
        PyErr_SetString(pyfr_ErrorRadius, "Failed decoding packet");
        goto error;
    }

    /* Add the virtual Packet-Type attribute */
    vp = fr_pair_afrom_child_num(NULL, fr_dict_root(dict_radius), FR_PACKET_TYPE);
    if (!vp) {
        PyErr_SetString(pyfr_ErrorRadius, "Failed fr_pair_afrom_child_num(..., ..., FR_PACKET_TYPE)");
        goto error;
    }
    vp->vp_uint32 = kdata[0];
    fr_pair_prepend(&tmp_list, vp);

    /* Set packet id */
    packet_id = kdata[1];

    /* let's walkthrough the packets */
    attrs = PyDict_New();
    for (vp = fr_pair_dcursor_init(&cursor, &tmp_list);
         vp;
         vp = fr_dcursor_next(&cursor)) {
        PyObject *value_list;
        char lhs[64], rhs[128];

        PAIR_VERIFY(vp);

        DEBUG2("Decoding %pP", vp);

        fr_dict_attr_oid_print(&FR_SBUFF_OUT(lhs, sizeof(lhs)), NULL, vp->da, false);
        fr_pair_print_value_quoted(&FR_SBUFF_OUT(rhs, sizeof(rhs)), vp, T_BARE_WORD);

        /* the RHS already exists? then, append it */
        value_list = PyDict_GetItemString(attrs, lhs);
        if (!value_list) value_list = PyList_New(0);

        PyList_Append(value_list, PyUnicode_FromString(rhs));
        PyDict_SetItemString(attrs, lhs, value_list);
    }

    /* then, built the return */
    ret = Py_BuildValue("i,O", packet_id, attrs);
    if (!ret) {
        PyErr_SetString(pyfr_ErrorRadius, "Py_BuildValue() failed.");
        goto error;
    }

error:
    TALLOC_FREE(secret);

    /* clean up and return result */
    fr_pair_list_free(&tmp_list);

    return ret;
}

PYFR_INTERNAL PyMemberDef pyfr_radius_members[] = {
    {"host", T_STRING, offsetof(pyfr_radius_ctx_t, auth_host), 0, "RADIUS host"},
    {"port", T_STRING, offsetof(pyfr_radius_ctx_t, auth_port), 0, "RADIUS port"},
    { NULL }  /* Sentinel */
};

/* List of functions defined in this module */
PYFR_INTERNAL PyMethodDef pyfr_radius_methods[] = {
    {
        "encode_pair", (PyCFunction)pyfr_radius_encode_pair, (METH_VARARGS | METH_KEYWORDS),
        "Encode a data structure into a RADIUS attribute."
        "This is the main entry point into the encoder.  It sets up the encoder array"
        "we use for tracking our TLV/VSA nesting and then calls the appropriate"
        "dispatch function."
    },

    {
        "decode_pair", (PyCFunction)pyfr_radius_decode_pair, (METH_VARARGS | METH_KEYWORDS),
        "Decode a raw RADIUS packet into VPs."
    },

    {
        "encode_packet", (PyCFunction)pyfr_radius_encode_packet, (METH_VARARGS | METH_KEYWORDS),
        "Encode a data structure into a RADIUS attribute and reply as a dict() table."
        "This is the main entry point into the encoder.  It sets up the encoder array"
        "we use for tracking our TLV/VSA nesting and then calls the appropriate"
        "dispatch function."
    },

    {
        "decode_packet", (PyCFunction)pyfr_radius_decode_packet, (METH_VARARGS | METH_KEYWORDS),
        "Decode a raw RADIUS packet into VPs."
        "It returns: packet_id, attrs"
    },

    { NULL }
};

PYFR_INTERNAL PyTypeObject pyfr_radius_ctx_types = {
    PyVarObject_HEAD_INIT(NULL, 0) "pyfr.Radius",                /* tp_name */
    sizeof(pyfr_radius_ctx_t),                                   /* tp_basicsize */
    0,                                                           /* tp_itemsize */
    pyfr_radius_dealloc,                                         /* tp_dealloc */
    0,                                                           /* tp_print */
    0,                                                           /* tp_getattr */
    0,                                                           /* tp_setattr */
    0,                                                           /* tp_reserved */
    0,                                                           /* tp_repr */
    0,                                                           /* tp_as_number */
    0,                                                           /* tp_as_sequence */
    0,                                                           /* tp_as_mapping */
    0,                                                           /* tp_hash  */
    0,                                                           /* tp_call */
    0,                                                           /* tp_str */
    0,                                                           /* tp_getattro */
    0,                                                           /* tp_setattro */
    0,                                                           /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,                    /* tp_flags*/
    "Object to use libfreeradius-radius library.",               /* tp_doc */
    0,                                                           /* tp_traverse */
    0,                                                           /* tp_clear */
    0,                                                           /* tp_richcompare */
    0,                                                           /* tp_weaklistoffset */
    0,                                                           /* tp_iter */
    0,                                                           /* tp_iternext */
    pyfr_radius_methods,                                         /* tp_methods */
    pyfr_radius_members,                                         /* tp_members */
    0,                                                           /* tp_getset */
    0,                                                           /* tp_base */
    0,                                                           /* tp_dict */
    0,                                                           /* tp_descr_get */
    0,                                                           /* tp_descr_set */
    0,                                                           /* tp_dictoffset */
    pyfr_radius_init,                                            /* tp_init */
    0,                                                           /* tp_alloc */
    pyfr_radius_new,                                             /* tp_new */
};

PyTypeObject *pyfr_radius_register(void)
{
    DEBUG2("Loading pyfr.Radius");

    return &pyfr_radius_ctx_types;
}
