Helpful coding methods
======================

The following is a short set of guidelines to follow while
programming.  It does not address coding styles, function naming
methods, or debugging methods.  Rather, it describes the processes
which SHOULD go on in the programmers mind, while he is programming.

Coding standards apply to function names, the look of the code, and
coding consistency.  Coding methods apply to the daily practices used
by the programmer to write code.



1. Comment your code.

    If you don't, you'll be forced to debug it 6 months later, when
    you have no clue as to what it's doing.

    If someone REALLY hates you, you'll be forced to debug
    un-commented code that someone else wrote.  You don't want to do
    that.


2. Give things reasonable names.

   Variables and functions should have names.  Calling them 'x',
   'xx', and 'xxx' makes your life hell.  Even 'foo' and 'i' are
   problematic.


3. Check input parameters in the functions you write.

   Your function CANNOT do anything right if the user passed in
   garbage, and you were too lazy to check for garbage input.

   assert() is ugly.  Use it.

   GIGO is wrong.  If your function gets garbage input, it
   should complain loudly and with great descriptiveness.


4. Write useful error messages.

   "Function failed" is useless as an error message.  It makes
   debugging the code impossible without source-level instrumentation.

   If you're going to instrument the code at source level for error
   messages, leave the error messages there, so the next sucker won't
   have to do the same work all over again.


5. Check error conditions from the functions you call.

   Your function CANNOT do anything right if you called another
   function, and they gave you garbage output.

   One of the most common mistakes is::

    fp = fopen(...);
    fgetc(fp);                 /* core dumps! */

   If the programmer had bothered to check for a NULL fp (error
   condition), then he could have produced a DESCRIPTIVE error
   message, instead of having his program core dump.


6. Core dumps are for weenies.

   If your program core dumps accidentally, you're a bad programmer.
   You don't know what your program is doing, or what it's supposed
   to be doing when anything goes wrong.

   If it hits an assert() and calls abort(), you're a genius.  You've
   thought ahead to what MIGHT go wrong, and put in an assertion to
   ensure that it fails in a KNOWN MANNER when something DOES go
   wrong.  (As it usually does...)


7. Initialize your variables.

   memset() is your friend.  'ptr = NULL' is nice, too.

   Having variables containing garbage values makes it easy for the
   code to do garbage things.  The contents of local variables are
   inputs to your function.  See #3.

   It's also nearly impossible for you to debug any problems, as you
   can't tell the variables with garbage values from the real ones.


8. Don't allow buffer over-runs.

   They're usually accidental, but they cause core dumps.
   strcpy() and strcat() are ugly.  Use them under duress.

   sizeof() is your friend.


9. 'const' is your friend.

   If you don't mean to modify an input structure to your function,
   declare it 'const'.  Declare string constants 'const'.  It can't
   hurt, and it allows more errors to be found at compile time.

   Use 'const' everywhere.  Once you throw a few into your code, and
   have it save you from stupid bugs, you'll blindly throw in 'const'
   everywhere.  It's a life-saver.


10. Use C compiler warnings.

    Turn on all of the C compiler warnings possible.  You might have
    to turn some off due to broken system header files, though.  But
    the more warnings the merrier.

    Getting error messages at compile time is much preferable to
    getting core dumps at run time.  See #7.

    Notice that the C compiler error messages are helpful?  You should
    write error messages like this, too.  See #4.


11. Avoid UNIXisms and ASCIIisms and visualisms.

    You don't know under what system someone will try to run your code.
    Don't demand that others use the same OS or character set as you use.

    Never assign numbers to pointers.  If foo is a char*, and you want it
    to be be null, assign NULL, not 0.  The zeroth location is perfectly
    as addressable as any other on plenty of OSes.  Not all the world
    runs on Unix (though it should :) ).

    Another common mistake is to assume that the zeroth character in the
    character set is the string terminator.  Instead of terminating a
    string with 0, use '\0', which is always right.  Similarly, memset()
    with the appropriate value:  NULL, '\0', or 0 for pointers, chars,
    and numbers.

    Don't put tabs in string constants, either.  Always use '\t' to
    represent a tab, instead of ASCII 9.  Literal tabs are presented to
    readers of your code as arbitrary whitespace, and it's easy to mess
    up.


12. Make conditionals explicit.

    Though it's legal to test "if (foo){}", if you test against the
    appropriate value (like NULL or '\0'), your code is prettier and
    easier for others to read without having to eyeball your prototypes
    continuously to figure out what you're doing (especially if your
    variables aren't well-named).  See #2.


13. Test your code.

    Even Donald Knuth writes buggy code.  You'll never find all of the
    bugs in your code unless you write a test program for it.

    This also means that you'll have to write your code so that it
    will be easily testable.  As a result, it will look better, and be
    easier to debug.
