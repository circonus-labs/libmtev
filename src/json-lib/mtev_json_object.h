/*
 * $Id: mtev_json_object.h,v 1.12 2006/01/30 23:07:57 mclark Exp $
 *
 * Copyright (c) 2004, 2005 Metaparadigm Pte. Ltd.
 * Michael Clark <michael@metaparadigm.com>
 * Copyright (c) 2015, Circonus, Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See COPYING for details.
 *
 */

#ifndef _mtev_json_object_h_
#define _mtev_json_object_h_

#ifdef __cplusplus
extern "C" {
#endif

#define JSON_OBJECT_DEF_HASH_ENTRIES 16

#undef FALSE
#define FALSE ((boolean)0)

#undef TRUE
#define TRUE ((boolean)1)

extern const char *mtev_json_number_chars;
extern const char *mtev_json_hex_chars;

/* forward structure definitions */

typedef int boolean;
typedef struct jl_printbuf jl_printbuf;
typedef struct jl_lh_table jl_lh_table;
typedef struct jl_array_list jl_array_list;
typedef struct mtev_json_object mtev_json_object;
typedef struct mtev_json_object_iter mtev_json_object_iter;
typedef struct mtev_json_tokener mtev_json_tokener;

/* supported object types */

typedef enum mtev_json_type {
  mtev_json_type_null,
  mtev_json_type_boolean,
  mtev_json_type_double,
  mtev_json_type_int,
  mtev_json_type_object,
  mtev_json_type_array,
  mtev_json_type_string
} mtev_json_type;

typedef enum mtev_json_int_overflow {
  mtev_json_overflow_int,
  mtev_json_overflow_uint64,
  mtev_json_overflow_int64
} mtev_json_int_overflow;

/* reference counting functions */

/**
 * Increment the reference count of mtev_json_object
 * @param obj the mtev_json_object instance
 */
extern struct mtev_json_object* mtev_json_object_get(struct mtev_json_object *obj);

/**
 * Decrement the reference count of mtev_json_object and free if it reaches zero
 * @param obj the mtev_json_object instance
 */
extern void mtev_json_object_put(struct mtev_json_object *obj);

/**
 * Check if the mtev_json_object is of a given type
 * @param obj the mtev_json_object instance
 * @param type one of:
     mtev_json_type_boolean,
     mtev_json_type_double,
     mtev_json_type_int,
     mtev_json_type_object,
     mtev_json_type_array,
     mtev_json_type_string,
 */
extern int mtev_json_object_is_type(struct mtev_json_object *obj, enum mtev_json_type type);

/**
 * Get the type of the mtev_json_object
 * @param obj the mtev_json_object instance
 * @returns type being one of:
     mtev_json_type_boolean,
     mtev_json_type_double,
     mtev_json_type_int,
     mtev_json_type_object,
     mtev_json_type_array,
     mtev_json_type_string,
 */
extern enum mtev_json_type mtev_json_object_get_type(struct mtev_json_object *obj);


/** Stringify object to json format
 * @param obj the mtev_json_object instance
 * @returns a string in JSON format
 */
extern const char* mtev_json_object_to_json_string(struct mtev_json_object *obj);


/* object type methods */

/** Create a new empty object
 * @returns a mtev_json_object of type mtev_json_type_object
 */
extern struct mtev_json_object* mtev_json_object_new_object(void);

/** Get the hashtable of a mtev_json_object of type mtev_json_type_object
 * @param obj the mtev_json_object instance
 * @returns a linkhash
 */
extern struct jl_lh_table* mtev_json_object_get_object(struct mtev_json_object *obj);

/** Add an object field to a mtev_json_object of type mtev_json_type_object
 *
 * The reference count will *not* be incremented. This is to make adding
 * fields to objects in code more compact. If you want to retain a reference
 * to an added object you must wrap the passed object with mtev_json_object_get
 *
 * @param obj the mtev_json_object instance
 * @param key the object field name (a private copy will be duplicated)
 * @param val a mtev_json_object or NULL member to associate with the given field
 */
extern void mtev_json_object_object_add(struct mtev_json_object* obj, const char *key,
				   struct mtev_json_object *val);

/** Get the mtev_json_object associate with a given object field
 * @param obj the mtev_json_object instance
 * @param key the object field name
 * @returns the mtev_json_object associated with the given field name
 */
extern struct mtev_json_object* mtev_json_object_object_get(struct mtev_json_object* obj,
						  const char *key);

/** Delete the given mtev_json_object field
 *
 * The reference count will be decremented for the deleted object
 *
 * @param obj the mtev_json_object instance
 * @param key the object field name
 */
extern void mtev_json_object_object_del(struct mtev_json_object* obj, const char *key);

/** Iterate through all keys and values of an object
 * @param obj the mtev_json_object instance
 * @param key the local name for the char* key variable defined in the body
 * @param val the local name for the mtev_json_object* object variable defined in the body
 */
#if defined(__GNUC__) && !defined(__STRICT_ANSI__)

# define mtev_json_object_object_foreach(obj,key,val) \
 char *key; struct mtev_json_object *val; \
 for(struct jl_lh_entry *entry = mtev_json_object_get_object(obj)->head; ({ if(entry) { key = (char*)entry->k; val = (struct mtev_json_object*)entry->v; } ; entry; }); entry = entry->next )

#else /* ANSI C or MSC */

# define mtev_json_object_object_foreach(obj,key,val) \
 char *key; struct mtev_json_object *val; struct jl_lh_entry *entry; \
 for(entry = mtev_json_object_get_object(obj)->head; (entry ? (key = (char*)entry->k, val = (struct mtev_json_object*)entry->v, entry) : 0); entry = entry->next)

#endif /* defined(__GNUC__) && !defined(__STRICT_ANSI__) */

/** Iterate through all keys and values of an object (ANSI C Safe)
 * @param obj the mtev_json_object instance
 * @param iter the object iterator
 */
#define mtev_json_object_object_foreachC(obj,iter) \
 for(iter.entry = mtev_json_object_get_object(obj)->head; (iter.entry ? (iter.key = (char*)iter.entry->k, iter.val = (struct mtev_json_object*)iter.entry->v, iter.entry) : 0); iter.entry = iter.entry->next)

/* Array type methods */

/** Create a new empty mtev_json_object of type mtev_json_type_array
 * @returns a mtev_json_object of type mtev_json_type_array
 */
extern struct mtev_json_object* mtev_json_object_new_array(void);

/** Get the arraylist of a mtev_json_object of type mtev_json_type_array
 * @param obj the mtev_json_object instance
 * @returns an arraylist
 */
extern struct jl_array_list* mtev_json_object_get_array(struct mtev_json_object *obj);

/** Get the length of a mtev_json_object of type mtev_json_type_array
 * @param obj the mtev_json_object instance
 * @returns an int
 */
extern int mtev_json_object_array_length(struct mtev_json_object *obj);

/** Add an element to the end of a mtev_json_object of type mtev_json_type_array
 *
 * The reference count will *not* be incremented. This is to make adding
 * fields to objects in code more compact. If you want to retain a reference
 * to an added object you must wrap the passed object with mtev_json_object_get
 *
 * @param obj the mtev_json_object instance
 * @param val the mtev_json_object to be added
 */
extern int mtev_json_object_array_add(struct mtev_json_object *obj,
				 struct mtev_json_object *val);

/** Insert or replace an element at a specified index in an array (a mtev_json_object of type mtev_json_type_array)
 *
 * The reference count will *not* be incremented. This is to make adding
 * fields to objects in code more compact. If you want to retain a reference
 * to an added object you must wrap the passed object with mtev_json_object_get
 *
 * The reference count of a replaced object will be decremented.
 *
 * The array size will be automatically be expanded to the size of the
 * index if the index is larger than the current size.
 *
 * @param obj the mtev_json_object instance
 * @param idx the index to insert the element at
 * @param val the mtev_json_object to be added
 */
extern int mtev_json_object_array_put_idx(struct mtev_json_object *obj, int idx,
				     struct mtev_json_object *val);

/** Get the element at specificed index of the array (a mtev_json_object of type mtev_json_type_array)
 * @param obj the mtev_json_object instance
 * @param idx the index to get the element at
 * @returns the mtev_json_object at the specified index (or NULL)
 */
extern struct mtev_json_object* mtev_json_object_array_get_idx(struct mtev_json_object *obj,
						     int idx);

/* boolean type methods */

/** Create a new empty mtev_json_object of type mtev_json_type_boolean
 * @param b a boolean TRUE or FALSE (0 or 1)
 * @returns a mtev_json_object of type mtev_json_type_boolean
 */
extern struct mtev_json_object* mtev_json_object_new_boolean(boolean b);

/** Get the boolean value of a mtev_json_object
 *
 * The type is coerced to a boolean if the passed object is not a boolean.
 * integer and double objects will return FALSE if there value is zero
 * or TRUE otherwise. If the passed object is a string it will return
 * TRUE if it has a non zero length. If any other object type is passed
 * TRUE will be returned if the object is not NULL.
 *
 * @param obj the mtev_json_object instance
 * @returns a boolean
 */
extern boolean mtev_json_object_get_boolean(struct mtev_json_object *obj);


/* int type methods */

/** Create a new empty mtev_json_object of type mtev_json_type_int
 * @param i the integer
 * @returns a mtev_json_object of type mtev_json_type_int
 */
extern struct mtev_json_object* mtev_json_object_new_int(int i);
extern struct mtev_json_object *mtev_json_object_new_int64(int64_t i);
extern struct mtev_json_object *mtev_json_object_new_uint64(uint64_t i);

extern mtev_json_int_overflow mtev_json_object_get_int_overflow(struct mtev_json_object *jso);
extern void mtev_json_object_set_int_overflow(struct mtev_json_object *jso,
					  mtev_json_int_overflow o);
extern uint64_t mtev_json_object_get_uint64(struct mtev_json_object *jso);
extern int64_t mtev_json_object_get_int64(struct mtev_json_object *jso);
extern void mtev_json_object_set_uint64(struct mtev_json_object *jso, uint64_t v);
extern void mtev_json_object_set_int64(struct mtev_json_object *jso, int64_t v);

/** Get the int value of a mtev_json_object
 *
 * The type is coerced to a int if the passed object is not a int.
 * double objects will return their integer conversion. Strings will be
 * parsed as an integer. If no conversion exists then 0 is returned.
 *
 * @param obj the mtev_json_object instance
 * @returns an int
 */
extern int mtev_json_object_get_int(struct mtev_json_object *obj);


/* double type methods */

/** Create a new empty mtev_json_object of type mtev_json_type_double
 * @param d the double
 * @returns a mtev_json_object of type mtev_json_type_double
 */
extern struct mtev_json_object* mtev_json_object_new_double(double d);

/** Get the double value of a mtev_json_object
 *
 * The type is coerced to a double if the passed object is not a double.
 * integer objects will return their dboule conversion. Strings will be
 * parsed as a double. If no conversion exists then 0.0 is returned.
 *
 * @param obj the mtev_json_object instance
 * @returns an double
 */
extern double mtev_json_object_get_double(struct mtev_json_object *obj);


/* string type methods */

/** Create a new empty mtev_json_object of type mtev_json_type_string
 *
 * A copy of the string is made and the memory is managed by the mtev_json_object
 *
 * @param s the string
 * @returns a mtev_json_object of type mtev_json_type_string
 */
extern struct mtev_json_object* mtev_json_object_new_string(const char *s);

extern struct mtev_json_object* mtev_json_object_new_string_len(const char *s, int len);

/** Get the string value of a mtev_json_object
 *
 * If the passed object is not of type mtev_json_type_string then the JSON
 * representation of the object is returned.
 *
 * The returned string memory is managed by the mtev_json_object and will
 * be freed when the reference count of the mtev_json_object drops to zero.
 *
 * @param obj the mtev_json_object instance
 * @returns a string
 */
extern const char* mtev_json_object_get_string(struct mtev_json_object *obj);

#ifdef __cplusplus
}
#endif

#if JSON_LIB_COMPAT == 1
#define json_number_chars mtev_json_number_chars
#define json_hex_chars mtev_json_hex_chars
#define json_object mtev_json_object
#define json_object_iter mtev_json_object_iter
#define json_tokener mtev_json_tokener
#define json_type mtev_json_type
#define json_int_overflow mtev_json_int_overflow
#define json_object_get mtev_json_object_get
#define json_object_put mtev_json_object_put
#define json_object_is_type mtev_json_object_is_type
#define json_object_get_type mtev_json_object_get_type
#define json_object_to_json_string mtev_json_object_to_json_string
#define json_object_new_object mtev_json_object_new_object
#define json_object_get_object mtev_json_object_get_object
#define json_object_object_add mtev_json_object_object_add
#define json_object_object_get mtev_json_object_object_get
#define json_object_object_del mtev_json_object_object_del
#define json_object_new_array mtev_json_object_new_array
#define json_object_get_array mtev_json_object_get_array
#define json_object_array_length mtev_json_object_array_length
#define json_object_array_add mtev_json_object_array_add
#define json_object_array_put_idx mtev_json_object_array_put_idx
#define json_object_array_get_idx mtev_json_object_array_get_idx
#define json_object_new_boolean mtev_json_object_new_boolean
#define json_object_get_boolean mtev_json_object_get_boolean
#define json_object_new_int mtev_json_object_new_int
#define json_object_get_int_overflow mtev_json_object_get_int_overflow
#define json_object_set_int_overflow mtev_json_object_set_int_overflow
#define json_object_get_uint64 mtev_json_object_get_uint64
#define json_object_get_int64 mtev_json_object_get_int64
#define json_object_set_uint64 mtev_json_object_set_uint64
#define json_object_set_int64 mtev_json_object_set_int64
#define json_object_get_int mtev_json_object_get_int
#define json_object_new_double mtev_json_object_new_double
#define json_object_get_double mtev_json_object_get_double
#define json_object_new_string mtev_json_object_new_string
#define json_object_new_string_len mtev_json_object_new_string_len
#define json_object_get_string mtev_json_object_get_string

#define json_object_object_foreach mtev_json_object_object_foreach
#define json_object_object_foreachC mtev_json_object_object_foreachC

#define json_type_null mtev_json_type_null
#define json_type_boolean mtev_json_type_boolean
#define json_type_double mtev_json_type_double
#define json_type_int mtev_json_type_int
#define json_type_object mtev_json_type_object
#define json_type_array mtev_json_type_array
#define json_type_string mtev_json_type_string
#define json_overflow_int mtev_json_overflow_int
#define json_overflow_uint64 mtev_json_overflow_uint64
#define json_overflow_int64 mtev_json_overflow_int64

#endif

#endif
