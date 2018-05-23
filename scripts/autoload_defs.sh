#!/bin/bash

PATH="$PATH:./build/bin/local"
NEED_INTERNAL=false
NEED_RADIUS=false

IFS=$'\n'
for i in $@; do
	ATTR_DEFS+=($(grep -o -E 'FR_[[:alnum:]_]*' "$i" | sort | uniq | sed -e 's/^FR_//;s/_/-/g'))
	ATTR_DEFS+=($(grep -E 'fr_pair_make' "$i" | cut -d ',' -f 3 | sed -e 's/"//g;s/^ *//;s/ *$//'))
	ATTR_DEFS+=($(grep -E 'pair_make_(request|reply|config)' "$i" | cut -d ',' -f 1 | sed -e 's/^.*(//;s/"//g;s/^ *//;s/ *$//'))
	ATTR_DEFS+=($(grep -E 'fr_dict_attr_by_name' "$i" | cut -d ',' -f 2 | sed -e 's/"//g;s/^ *//;s/ *$//;s/);//'))
done

for i in $@; do
	if echo $i | grep '[.]c$' > /dev/null; then
		FILE=$(basename $i .c)
		break
	fi
done

RESOLVED=($(radict -- ${ATTR_DEFS[*]} | grep -oE ".*\t.*\t.*\t.*\t(internal)?" | sort -k3 | sort -s -r -k5 | uniq))

for i in ${RESOLVED[*]}; do
	if echo $i | cut -f 5 | grep 'internal' > /dev/null; then
		NEED_INTERNAL=true
	else
		NEED_RADIUS=true
	fi

	ATTRS+=($(echo $i | cut -f 3 | sed -e 's/-/_/g' | tr '[:upper:]' '[:lower:]'))
done

if $NEED_INTERNAL; then
	echo "static fr_dict_t *dict_freeradius;"
fi

if $NEED_RADIUS; then
	echo "static fr_dict_t *dict_radius;"
fi

echo

printf "extern fr_dict_autoload_t %s_dict[];\n" $FILE
printf "fr_dict_autoload_t %s_dict[] = {\n" $FILE

if $NEED_INTERNAL; then
	printf "\t{ .out = &dict_freeradius, .proto = \"freeradius\" },\n"
fi

if $NEED_RADIUS; then
	printf "\t{ .out = &dict_radius, .proto = \"radius\" },\n"
fi

printf "\t{ NULL }\n"
printf "};\n"

echo

for i in ${ATTRS[*]}; do
	printf "static fr_dict_attr_t const *attr_%s;\n" $i
done

echo

printf "extern fr_dict_attr_autoload_t %s_dict_attr[];\n" $FILE
printf "fr_dict_attr_autoload_t %s_dict_attr[] = {\n" $FILE

for i in ${RESOLVED[*]}; do
	if echo $i | cut -f 5 | grep 'internal' > /dev/null; then
		DICT="dict_freeradius"
	else
		DICT="dict_radius"
	fi

	NAME=$(echo $i | cut -f 3)
	VAR=$(echo $NAME | sed -e 's/-/_/g' | tr '[:upper:]' '[:lower:]')

	case $(echo $i | cut -f 4) in
	'string')
		TYPE="FR_TYPE_STRING"
		;;

	'octets')
		TYPE="FR_TYPE_OCTETS"
		;;

	'ipaddr')
		TYPE="FR_TYPE_IPV4_ADDR"
		;;

	'ipv4prefix')
		TYPE="FR_TYPE_IPV4_PREFIX"
		;;

	'ipv6addr')
		TYPE="FR_TYPE_IPV6_ADDR"
		;;

	'ipv6prefix')
		TYPE="FR_TYPE_IPV6_PREFIX"
		;;

	'ifid')
		TYPE="FR_TYPE_IFID"
		;;

	'ether')
		TYPE="FR_TYPE_ETHERNET"
		;;

	'bool')
		TYPE="FR_TYPE_BOOL"
		;;

	'uint8')
		TYPE="FR_TYPE_UINT8"
		;;

	'uint16')
		TYPE="FR_TYPE_UINT16"
		;;

	'uint32')
		TYPE="FR_TYPE_UINT32"
		;;

	'uint64')
		TYPE="FR_TYPE_UINT64"
		;;

	'int8')
		TYPE="FR_TYPE_INT8"
		;;

	'int16')
		TYPE="FR_TYPE_INT16"
		;;

	'int32')
		TYPE="FR_TYPE_INT32"
		;;

	'int64')
		TYPE="FR_TYPE_INT64"
		;;

	'int64')
		TYPE="FR_TYPE_INT64"
		;;

	'float32')
		TYPE="FR_TYPE_FLOAT32"
		;;

	'float64')
		TYPE="FR_TYPE_FLOAT64"
		;;

	'date')
		TYPE="FR_TYPE_DATE"
		;;

	'extended')
		TYPE="FR_TYPE_EXTENDED"
		;;

	'tlv')
		TYPE="FR_TYPE_TLV"
		;;

	*)
		TYPE="FR_UNKNOWN"
		;;
	esac

	printf "\t{ .out = &attr_%s, .name = \"%s\", .type = %s, .dict = &%s },\n" $VAR $NAME $TYPE $DICT
done

printf "\t{ NULL }\n"
printf "};\n"
