#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

//#include "internal.h"
#include <string.h>

typedef enum {
	CTC_Space = 0x1,
	CTC_Letter = 0x2,
	CTC_Digit = 0x4,
	CTC_Punctuation = 0x8,
	CTC_UpperCase = 0x10,
	CTC_LowerCase = 0x20,
	CTC_Math = 0x40,
	CTC_Sign = 0x80,
	CTC_LitDigit = 0x100,
	CTC_Class1 = 0x200,
	CTC_Class2 = 0x400,
	CTC_Class3 = 0x800,
	CTC_Class4 = 0x1000,
	CTC_SeqDelimiter = 0x2000,
	CTC_SeqBefore = 0x4000,
	CTC_SeqAfter = 0x8000,
	CTC_UserDefined0 = 0x10000,
	CTC_UserDefined1 = 0x20000,
	CTC_UserDefined2 = 0x40000,
	CTC_UserDefined3 = 0x80000,
	CTC_UserDefined4 = 0x100000,
	CTC_UserDefined5 = 0x200000,
	CTC_UserDefined6 = 0x400000,
	CTC_UserDefined7 = 0x800000,
	CTC_CapsMode = 0x1000000,
	CTC_NumericMode = 0x2000000,
	CTC_NumericNoContract = 0x4000000,
	CTC_EndOfInput = 0x8000000,  // only used by pattern matcher
	CTC_EmpMatch = 0x10000000,   // only used in TranslationTableRule->before and
								 // TranslationTableRule->after
} TranslationTableCharacterAttribute;

enum pattern_type {
	PTN_ERROR,

	PTN_START,
	PTN_GROUP,
	PTN_NOT,

	PTN_ONE_MORE,
	PTN_ZERO_MORE,
	PTN_OPTIONAL,

	PTN_ALTERNATE,

	PTN_ANY,
	PTN_ATTRIBUTES,
	PTN_CHARS,
	PTN_HOOK,
	PTN_END_OF_INPUT,

	PTN_END = 0xffff,
};

typedef unsigned short int widechar;

#define EXPR_TYPE_IN(at, buffer) (buffer[(at) + 0])
#define EXPR_PRV_IN(at, buffer) (buffer[(at) + 1])
#define EXPR_NXT_IN(at, buffer) (buffer[(at) + 2])
#define EXPR_DATA_0_IN(at, buffer) (buffer[(at) + 3])
#define EXPR_DATA_1_IN(at, buffer) (buffer[(at) + 4])
#define EXPR_DATA_2_IN(at, buffer) (buffer[(at) + 5])
#define EXPR_DATA_IN(at, buffer) ((widechar *)&buffer[(at) + 3])
#define EXPR_CONST_DATA_IN(at, buffer) ((const widechar *)&buffer[(at) + 3])

#define EXPR_TYPE(at) EXPR_TYPE_IN((at), expr_data)
#define EXPR_PRV(at) EXPR_PRV_IN((at), expr_data)
#define EXPR_NXT(at) EXPR_NXT_IN((at), expr_data)
#define EXPR_DATA_0(at) EXPR_DATA_0_IN((at), expr_data)
#define EXPR_DATA_1(at) EXPR_DATA_1_IN((at), expr_data)
#define EXPR_DATA_2(at) EXPR_DATA_2_IN((at), expr_data)
#define EXPR_DATA(at) EXPR_DATA_IN((at), expr_data)
#define EXPR_CONST_DATA(at) EXPR_CONST_DATA_IN((at), expr_data)


static int
pattern_compile_expression(const widechar *input, const int input_max, int *input_crs,
		widechar *expr_data, const int expr_max, widechar *expr_crs,
		widechar *loop_cnts);

static int
pattern_compile_1(const widechar *input, const int input_max, int *input_crs,
		widechar *expr_data, const int expr_max, widechar *expr_crs,
		widechar *loop_cnts) {
	int expr_crs_prv;

	if (*expr_crs + 6 >= expr_max) return 0;

	expr_crs_prv = *expr_crs;

	/* setup start expression */
	EXPR_TYPE(*expr_crs) = PTN_START;
	EXPR_PRV(*expr_crs) = PTN_END;
	*expr_crs += 3;
	EXPR_NXT(expr_crs_prv) = *expr_crs;

	/* setup end expression */
	EXPR_TYPE(*expr_crs) = PTN_END;
	EXPR_PRV(*expr_crs) = expr_crs_prv;
	EXPR_NXT(*expr_crs) = PTN_END;

	while (*input_crs < input_max) {
		expr_crs_prv = *expr_crs;
		if (!pattern_compile_expression(input, input_max, input_crs, expr_data, expr_max,
					expr_crs, loop_cnts))
			return 0;

		/* setup end expression */
		if (*expr_crs + 3 >= expr_max) return 0;
		EXPR_NXT(expr_crs_prv) = *expr_crs;
		EXPR_TYPE(*expr_crs) = PTN_END;
		EXPR_PRV(*expr_crs) = expr_crs_prv;
		EXPR_NXT(*expr_crs) = PTN_END;

		/* insert seqafterexpression before attributes of seqafterchars */
		// if(EXPR_TYPE(expr_crs_prv) == PTN_ATTRIBUTES)
		// if(EXPR_DATA_1(expr_crs_prv) & CTC_SeqAfter)
		// {
		// 	i = 0;
		// 	pattern_insert_alternate(table->seqAfterExpression,
		// 		table->seqAfterExpressionLength, &i, expr_data, expr_max,
		// 		expr_crs, loop_cnts, expr_crs_prv);
		// }
	}

	return *expr_crs;
}

static int
pattern_compile_expression(const widechar *input, const int input_max, int *input_crs,
		widechar *expr_data, const int expr_max, widechar *expr_crs,
		widechar *loop_cnts) {
	widechar *data;
	int expr_start, expr_end, expr_sub, expr_crs_prv;
	int input_end;
	int attrs0, attrs1;
	int set, esc, nest, i;

	switch (input[*input_crs]) {
	case '(':

		if (*expr_crs + 10 >= expr_max) return 0;

		(*input_crs)++;
		if (*input_crs >= input_max) return 0;

		/* find closing parenthesis */
		nest = esc = 0;
		for (input_end = *input_crs; input_end < input_max; input_end++) {
			if (input[input_end] == '\\' && !esc) {
				esc = 1;
				continue;
			}

			if (input[input_end] == '(' && !esc)
				nest++;
			else if (input[input_end] == ')' && !esc) {
				if (nest)
					nest--;
				else
					break;
			}

			esc = 0;
		}
		if (input_end >= input_max) return 0;

		EXPR_TYPE(*expr_crs) = PTN_GROUP;

		/* compile sub expressions */
		expr_crs_prv = *expr_crs;
		*expr_crs += 4;
		EXPR_DATA_0(expr_crs_prv) = *expr_crs;
		expr_sub = *expr_crs;
		EXPR_TYPE(expr_sub) = PTN_ERROR;
		EXPR_PRV(expr_sub) = PTN_END;
		EXPR_NXT(expr_sub) = PTN_END;
		if (!pattern_compile_1(input, input_end, input_crs, expr_data, expr_max, expr_crs,
					loop_cnts))
			return 0;
		(*input_crs)++;

		/* reset end expression */
		expr_end = *expr_crs;
		EXPR_NXT(expr_end) = expr_crs_prv;

		return *expr_crs += 3;

	case '!':

		if (*expr_crs + 10 >= expr_max) return 0;

		(*input_crs)++;
		EXPR_TYPE(*expr_crs) = PTN_NOT;
		expr_crs_prv = *expr_crs;
		*expr_crs += 4;
		EXPR_DATA_0(expr_crs_prv) = *expr_crs;

		/* create start expression */
		expr_start = *expr_crs;
		EXPR_TYPE(expr_start) = PTN_START;
		EXPR_PRV(expr_start) = PTN_END;
		*expr_crs += 3;
		EXPR_NXT(expr_start) = *expr_crs;

		/* compile sub expression */
		expr_sub = *expr_crs;
		EXPR_TYPE(expr_sub) = PTN_ERROR;
		EXPR_PRV(expr_sub) = expr_start;
		EXPR_NXT(expr_sub) = PTN_END;

		if (!pattern_compile_expression(input, input_max, input_crs, expr_data, expr_max,
					expr_crs, loop_cnts))
			return 0;

		EXPR_NXT(expr_sub) = *expr_crs;

		/* create end expression */
		expr_end = *expr_crs;
		EXPR_TYPE(expr_end) = PTN_END;
		EXPR_PRV(expr_end) = expr_sub;
		EXPR_NXT(expr_end) = expr_crs_prv;

		return *expr_crs += 3;

	case '+':

		if (*expr_crs + 4 >= expr_max) return 0;
		EXPR_TYPE(*expr_crs) = PTN_ONE_MORE;
		EXPR_DATA_1(*expr_crs) = (*loop_cnts)++;
		(*input_crs)++;
		return *expr_crs += 5;

	case '*':

		if (*expr_crs + 4 >= expr_max) return 0;
		EXPR_TYPE(*expr_crs) = PTN_ZERO_MORE;
		EXPR_DATA_1(*expr_crs) = (*loop_cnts)++;
		(*input_crs)++;
		return *expr_crs += 5;

	case '?':

		if (*expr_crs + 4 >= expr_max) return 0;
		EXPR_TYPE(*expr_crs) = PTN_OPTIONAL;
		(*input_crs)++;
		return *expr_crs += 4;

	case '|':

		if (*expr_crs + 5 >= expr_max) return 0;
		EXPR_TYPE(*expr_crs) = PTN_ALTERNATE;
		(*input_crs)++;
		return *expr_crs += 5;

	case '.':

		if (*expr_crs + 3 >= expr_max) return 0;
		EXPR_TYPE(*expr_crs) = PTN_ANY;
		(*input_crs)++;
		return *expr_crs += 3;

	case '%':

		if (*expr_crs + 5 >= expr_max) return 0;

		(*input_crs)++;
		if (*input_crs >= input_max) return 0;

		/* find closing bracket */
		if (input[*input_crs] == '[') {
			set = 1;
			(*input_crs)++;
			for (input_end = *input_crs; input_end < input_max; input_end++)
				if (input[input_end] == ']') break;
			if (input_end >= input_max) return 0;
		} else {
			set = 0;
			input_end = *input_crs + 1;
		}

		EXPR_TYPE(*expr_crs) = PTN_ATTRIBUTES;

		attrs0 = attrs1 = 0;
		for (; (*input_crs) < input_end; (*input_crs)++) {
			switch (input[*input_crs]) {
			case '_':
				attrs0 |= CTC_Space;
				break;
			case '#':
				attrs0 |= CTC_Digit;
				break;
			case 'a':
				attrs0 |= CTC_Letter;
				break;
			case 'u':
				attrs0 |= CTC_UpperCase;
				break;
			case 'l':
				attrs0 |= CTC_LowerCase;
				break;
			case '.':
				attrs0 |= CTC_Punctuation;
				break;
			case '$':
				attrs0 |= CTC_Sign;
				break;
			case '~':
				attrs0 |= CTC_SeqDelimiter;
				break;
			case '<':
				attrs0 |= CTC_SeqBefore;
				break;
			case '>':
				attrs0 |= CTC_SeqAfter;
				break;

			case '0':
				attrs1 |= (CTC_UserDefined0 >> 16);
				break;
			case '1':
				attrs1 |= (CTC_UserDefined1 >> 16);
				break;
			case '2':
				attrs1 |= (CTC_UserDefined2 >> 16);
				break;
			case '3':
				attrs1 |= (CTC_UserDefined3 >> 16);
				break;
			case '4':
				attrs1 |= (CTC_UserDefined4 >> 16);
				break;
			case '5':
				attrs1 |= (CTC_UserDefined5 >> 16);
				break;
			case '6':
				attrs1 |= (CTC_UserDefined6 >> 16);
				break;
			case '7':
				attrs1 |= (CTC_UserDefined7 >> 16);
				break;
			case '^':
				attrs1 |= (CTC_EndOfInput >> 16);
				break;

			default:
				return 0;
			}
		}
		EXPR_DATA_0(*expr_crs) = attrs1;
		EXPR_DATA_1(*expr_crs) = attrs0;

		if (set) (*input_crs)++;
		return *expr_crs += 5;

	case '[':

		(*input_crs)++;
		if (*input_crs >= input_max) return 0;

		/* find closing bracket */
		esc = 0;
		for (input_end = *input_crs; input_end < input_max; input_end++) {
			if (input[input_end] == '\\' && !esc) {
				esc = 1;
				continue;
			}

			if (input[input_end] == ']' && !esc) break;
			esc = 0;
		}
		if (input_end >= input_max) return 0;

		if (*expr_crs + 4 + (input_end - *input_crs) >= expr_max) return 0;

		EXPR_TYPE(*expr_crs) = PTN_CHARS;

		esc = 0;
		data = EXPR_DATA(*expr_crs);
		for (i = 1; *input_crs < input_end; (*input_crs)++) {
			if (input[*input_crs] == '\\' && !esc) {
				esc = 1;
				continue;
			}

			esc = 0;
			data[i++] = (widechar)input[*input_crs];
		}
		data[0] = i - 1;
		(*input_crs)++;
		return *expr_crs += 4 + data[0];

	case '@':

		(*input_crs)++;
		if (*input_crs >= input_max) return 0;

		/* find closing bracket */
		if (input[*input_crs] == '[') {
			set = 1;
			(*input_crs)++;
			for (input_end = *input_crs; input_end < input_max; input_end++)
				if (input[input_end] == ']') break;
			if (input_end >= input_max) return 0;
		} else {
			set = 0;
			input_end = *input_crs + 1;
		}

		if (*expr_crs + 4 + (input_end - *input_crs) >= expr_max) return 0;

		EXPR_TYPE(*expr_crs) = PTN_HOOK;

		esc = 0;
		data = EXPR_DATA(*expr_crs);
		for (i = 1; *input_crs < input_end; (*input_crs)++) {
			if (input[*input_crs] == '\\' && !esc) {
				esc = 1;
				continue;
			}

			esc = 0;
			data[i++] = (widechar)input[*input_crs];
		}
		data[0] = i - 1;
		if (set) (*input_crs)++;
		return *expr_crs += 4 + data[0];

	case '^':
	case '$':

		if (*expr_crs + 3 >= expr_max) return 0;
		EXPR_TYPE(*expr_crs) = PTN_END_OF_INPUT;
		(*input_crs)++;
		return *expr_crs += 3;

	case '\\':

		(*input_crs)++;
		if (*input_crs >= input_max) return 0;

	default:

		if (*expr_crs + 5 >= expr_max) return 0;
		EXPR_TYPE(*expr_crs) = PTN_CHARS;
		EXPR_DATA_0(*expr_crs) = 1;
		EXPR_DATA_1(*expr_crs) = (widechar)input[*input_crs];
		(*input_crs)++;
		return *expr_crs += 5;
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint16_t))
        return 0;

  const uint16_t *data = malloc(sizeof (uint16_t) * (Size/2 + 1));
  if (!data)
    return -1;
memcpy(data, Data, Size*sizeof(uint8_t));
  size_t size = Size/2;
    int g = Size;
  pattern_compile_expression(data, size, &g, data, size, data, data);
  return 0;
}