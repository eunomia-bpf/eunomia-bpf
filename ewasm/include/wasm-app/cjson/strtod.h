#ifndef WASM_STRTOD_H_
#define WASM_STRTOD_H_

double
strtod(const char *str, char **endptr)
{
    double result = 0.0;
    char signedResult = '\0';
    char signedExponent = '\0';
    int decimals = 0;
    int isExponent = false;
    int hasExponent = false;
    int hasResult = false;
    // exponent is logically int but is coded as double so that its eventual
    // overflow detection can be the same as for double result
    double exponent = 0;
    char c;

    for (; '\0' != (c = *str); ++str) {
        if ((c >= '0') && (c <= '9')) {
            int digit = c - '0';
            if (isExponent) {
                exponent = (10 * exponent) + digit;
                hasExponent = true;
            }
            else if (decimals == 0) {
                result = (10 * result) + digit;
                hasResult = true;
            }
            else {
                result += (double)digit / decimals;
                decimals *= 10;
            }
            continue;
        }

        if (c == '.') {
            if (!hasResult)
                break; // don't allow leading '.'
            if (isExponent)
                break; // don't allow decimal places in exponent
            if (decimals != 0)
                break; // this is the 2nd time we've found a '.'

            decimals = 10;
            continue;
        }

        if ((c == '-') || (c == '+')) {
            if (isExponent) {
                if (signedExponent || (exponent != 0))
                    break;
                else
                    signedExponent = c;
            }
            else {
                if (signedResult || (result != 0))
                    break;
                else
                    signedResult = c;
            }
            continue;
        }

        if (c == 'E') {
            if (!hasResult)
                break; // don't allow leading 'E'
            if (isExponent)
                break;
            else
                isExponent = true;
            continue;
        }

        break; // unexpected character
    }

    if (isExponent && !hasExponent) {
        while (*str != 'E')
            --str;
    }

    if (!hasResult && signedResult)
        --str;

    if (endptr)
        *endptr = (char *)(str);

    for (; exponent != 0; --exponent) {
        if (signedExponent == '-')
            result /= 10;
        else
            result *= 10;
    }

    if (signedResult == '-' && result != 0)
        result = -result;

    return result;
}

#endif // WASM_STRTOD_H_