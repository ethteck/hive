void func_004000A4(u32 arg0);                       /* static */
void func_00400224(u32 arg0);                       /* static */
void func_00400404(u32 arg0);                       /* static */
void func_004009F4(u32 arg0);                       /* static */
void func_00400FFC(u32 arg0);                       /* static */
void func_00401498(u32 arg0);                       /* static */

void test(u32 a) {
    func_004000A4(a);
    func_00400224(a);
    func_00400404(a);
    func_004009F4(a);
    func_00400FFC(a);
    func_00401498(a);
}

void func_004000A4(s8 arg0) {
    func_00400090((u32) (arg0 / 2));
    func_00400090((u32) (arg0 / 3));
    func_00400090((u32) (arg0 / 5));
    func_00400090((u32) (arg0 / 7));
    func_00400090((u32) (arg0 / 10));
    func_00400090((u32) (arg0 / 100));
    func_00400090((u32) (arg0 / 255));
    func_00400090((u32) (arg0 % 2));
    func_00400090((u32) (arg0 % 3));
    func_00400090((u32) (arg0 % 5));
    func_00400090((u32) (arg0 % 7));
    func_00400090((u32) (arg0 % 10));
    func_00400090((u32) (arg0 % 100));
    func_00400090((u32) (arg0 % 255));
}

void func_00400224(s16 arg0) {
    func_00400090((u32) (arg0 / 2));
    func_00400090((u32) (arg0 / 3));
    func_00400090((u32) (arg0 / 5));
    func_00400090((u32) (arg0 / 7));
    func_00400090((u32) (arg0 / 10));
    func_00400090((u32) (arg0 / 100));
    func_00400090((u32) (arg0 / 255));
    func_00400090((u32) (arg0 / 360));
    func_00400090((u32) (arg0 / 65534));
    func_00400090((u32) (arg0 % 2));
    func_00400090((u32) (arg0 % 3));
    func_00400090((u32) (arg0 % 5));
    func_00400090((u32) (arg0 % 7));
    func_00400090((u32) (arg0 % 10));
    func_00400090((u32) (arg0 % 100));
    func_00400090((u32) (arg0 % 255));
    func_00400090((u32) (arg0 % 360));
    func_00400090((u32) (arg0 % 65534));
}

void func_00400404(u32 arg0) {
    s32 phi_at;

    func_00400090(arg0);
    func_00400090((u32) ((s32) arg0 / 2));
    func_00400090((u32) ((s32) arg0 / 3));
    func_00400090((u32) ((s32) arg0 / 4));
    func_00400090((u32) ((s32) arg0 / 5));
    func_00400090((u32) ((s32) arg0 / 6));
    func_00400090((u32) ((s32) arg0 / 7));
    func_00400090((u32) ((s32) arg0 / 8));
    func_00400090((u32) ((s32) arg0 / 9));
    func_00400090((u32) ((s32) arg0 / 10));
    func_00400090((u32) ((s32) arg0 / 11));
    func_00400090((u32) ((s32) arg0 / 12));
    func_00400090((u32) ((s32) arg0 / 13));
    func_00400090((u32) ((s32) arg0 / 14));
    func_00400090((u32) ((s32) arg0 / 15));
    func_00400090((u32) ((s32) arg0 / 16));
    func_00400090((u32) ((s32) arg0 / 17));
    func_00400090((u32) ((s32) arg0 / 18));
    func_00400090((u32) ((s32) arg0 / 19));
    func_00400090((u32) ((s32) arg0 / 20));
    func_00400090((u32) ((s32) arg0 / 21));
    func_00400090((u32) ((s32) arg0 / 22));
    func_00400090((u32) ((s32) arg0 / 23));
    func_00400090((u32) ((s32) arg0 / 24));
    func_00400090((u32) ((s32) arg0 / 25));
    func_00400090((u32) ((s32) arg0 / 26));
    func_00400090((u32) ((s32) arg0 / 27));
    func_00400090((u32) ((s32) arg0 / 28));
    func_00400090((u32) ((s32) arg0 / 29));
    func_00400090((u32) ((s32) arg0 / 30));
    func_00400090((u32) ((s32) arg0 / 31));
    func_00400090((u32) ((s32) arg0 / 32));
    func_00400090((u32) ((s32) arg0 / 33));
    func_00400090((u32) ((s32) arg0 / 100));
    func_00400090((u32) ((s32) arg0 / 255));
    func_00400090((u32) ((s32) arg0 / 360));
    func_00400090((u32) ((s32) arg0 / 1000));
    func_00400090((u32) ((s32) arg0 / 10000));
    func_00400090((u32) ((s32) arg0 / 100000));
    func_00400090((u32) ((s32) arg0 / 1000000));
    func_00400090((u32) ((s32) arg0 / 9934464));
    func_00400090((u32) ((s32) arg0 / 89121024));
    func_00400090((u32) ((s32) arg0 / 1073741822));
    func_00400090((u32) ((s32) arg0 / 1073741823));
    phi_at = (s32) arg0;
    if ((s32) arg0 < 0) {
        phi_at = arg0 + 0x3FFFFFFF;
    }
    func_00400090((u32) (phi_at >> 0x1E));
    func_00400090((u32) ((s32) arg0 / 1073741825));
    func_00400090((u32) ((s32) arg0 / 2147483645));
    func_00400090((u32) ((s32) arg0 / 2147483646));
    func_00400090((u32) ((s32) arg0 / 2147483647));
    func_00400090(arg0 / 2147483648U);
    func_00400090((u32) ((s32) arg0 / 2147483649));
    func_00400090((u32) ((s32) arg0 / 2147483650));
    func_00400090((u32) ((s32) arg0 / -10));
    func_00400090((u32) ((s32) arg0 / -7));
    func_00400090((u32) ((s32) arg0 / -5));
    func_00400090((u32) -((s32) arg0 / 4));
    func_00400090((u32) ((s32) arg0 / -3));
    func_00400090((u32) -((s32) arg0 / 2));
    func_00400090((u32) -(s32) arg0);
}

void func_004009F4(s32 arg0) {
    func_00400090(0U);
    func_00400090((u32) (arg0 % 2));
    func_00400090((u32) (arg0 % 3));
    func_00400090((u32) (arg0 % 4));
    func_00400090((u32) (arg0 % 5));
    func_00400090((u32) (arg0 % 6));
    func_00400090((u32) (arg0 % 7));
    func_00400090((u32) (arg0 % 8));
    func_00400090((u32) (arg0 % 9));
    func_00400090((u32) (arg0 % 10));
    func_00400090((u32) (arg0 % 11));
    func_00400090((u32) (arg0 % 12));
    func_00400090((u32) (arg0 % 13));
    func_00400090((u32) (arg0 % 14));
    func_00400090((u32) (arg0 % 15));
    func_00400090((u32) (arg0 % 16));
    func_00400090((u32) (arg0 % 17));
    func_00400090((u32) (arg0 % 18));
    func_00400090((u32) (arg0 % 19));
    func_00400090((u32) (arg0 % 20));
    func_00400090((u32) (arg0 % 21));
    func_00400090((u32) (arg0 % 22));
    func_00400090((u32) (arg0 % 23));
    func_00400090((u32) (arg0 % 24));
    func_00400090((u32) (arg0 % 25));
    func_00400090((u32) (arg0 % 26));
    func_00400090((u32) (arg0 % 27));
    func_00400090((u32) (arg0 % 28));
    func_00400090((u32) (arg0 % 29));
    func_00400090((u32) (arg0 % 30));
    func_00400090((u32) (arg0 % 31));
    func_00400090((u32) (arg0 % 32));
    func_00400090((u32) (arg0 % 33));
    func_00400090((u32) (arg0 % 100));
    func_00400090((u32) (arg0 % 255));
    func_00400090((u32) (arg0 % 360));
    func_00400090((u32) (arg0 % 1000));
    func_00400090((u32) (arg0 % 10000));
    func_00400090((u32) (arg0 % 100000));
    func_00400090((u32) (arg0 % 1000000));
    func_00400090((u32) (arg0 % 9934464));
    func_00400090((u32) (arg0 % 89121024));
    func_00400090((u32) (arg0 % 1073741822));
    func_00400090((u32) (arg0 % 1073741823));
    func_00400090((u32) (arg0 % 1073741824));
    func_00400090((u32) (arg0 % 1073741825));
    func_00400090((u32) (arg0 % 2147483645));
    func_00400090((u32) (arg0 % 2147483646));
    func_00400090((u32) (arg0 % 2147483647));
    func_00400090((u32) arg0 % 2147483648U);
    func_00400090((u32) (arg0 % 2147483649));
    func_00400090((u32) (arg0 % 2147483650));
    func_00400090((u32) (arg0 % -10));
    func_00400090((u32) (arg0 % -7));
    func_00400090((u32) (arg0 % -5));
    func_00400090((u32) (arg0 % 4));
    func_00400090((u32) (arg0 % -3));
    func_00400090((u32) (arg0 % 2));
    func_00400090(0U);
}

void func_00400FFC(u32 arg0) {
    func_00400090(arg0);
    func_00400090(arg0 >> 1);
    func_00400090(arg0 / 3U);
    func_00400090(arg0 >> 2);
    func_00400090(arg0 / 5U);
    func_00400090(arg0 / 6U);
    func_00400090(arg0 / 7U);
    func_00400090(arg0 >> 3);
    func_00400090(arg0 / 9U);
    func_00400090(arg0 / 10U);
    func_00400090(arg0 / 11U);
    func_00400090(arg0 / 12U);
    func_00400090(arg0 / 13U);
    func_00400090(arg0 / 14U);
    func_00400090(arg0 / 15U);
    func_00400090(arg0 >> 4);
    func_00400090(arg0 / 17U);
    func_00400090(arg0 / 18U);
    func_00400090(arg0 / 19U);
    func_00400090(arg0 / 20U);
    func_00400090(arg0 / 21U);
    func_00400090(arg0 / 22U);
    func_00400090(arg0 / 23U);
    func_00400090(arg0 / 24U);
    func_00400090(arg0 / 25U);
    func_00400090(arg0 / 26U);
    func_00400090(arg0 / 27U);
    func_00400090(arg0 / 28U);
    func_00400090(arg0 / 29U);
    func_00400090(arg0 / 30U);
    func_00400090(arg0 / 31U);
    func_00400090(arg0 >> 5);
    func_00400090(arg0 / 33U);
    func_00400090(arg0 / 100U);
    func_00400090(arg0 / 255U);
    func_00400090(arg0 / 360U);
    func_00400090(arg0 / 1000U);
    func_00400090(arg0 / 10000U);
    func_00400090(arg0 / 100000U);
    func_00400090(arg0 / 1000000U);
    func_00400090(arg0 / 9934464U);
    func_00400090(arg0 / 89121024U);
    func_00400090(arg0 >> 0x1E);
    func_00400090(arg0 / 1073741825U);
    func_00400090(arg0 / 2147483646U);
    func_00400090(arg0 / 2147483647U);
    func_00400090(arg0 / 2147483648U);
    func_00400090(arg0 / 2147483649U);
    func_00400090(arg0 / -2U);
    func_00400090(arg0 / -1U);
}

void func_00401498(u32 arg0) {
    func_00400090(arg0);
    func_00400090(arg0 >> 1);
    func_00400090(arg0 / 3U);
    func_00400090(arg0 >> 2);
    func_00400090(arg0 / 5U);
    func_00400090(arg0 / 6U);
    func_00400090(arg0 / 7U);
    func_00400090(arg0 >> 3);
    func_00400090(arg0 / 9U);
    func_00400090(arg0 / 10U);
    func_00400090(arg0 / 11U);
    func_00400090(arg0 / 12U);
    func_00400090(arg0 / 13U);
    func_00400090(arg0 / 14U);
    func_00400090(arg0 / 15U);
    func_00400090(arg0 >> 4);
    func_00400090(arg0 / 17U);
    func_00400090(arg0 / 18U);
    func_00400090(arg0 / 19U);
    func_00400090(arg0 / 20U);
    func_00400090(arg0 / 21U);
    func_00400090(arg0 / 22U);
    func_00400090(arg0 / 23U);
    func_00400090(arg0 / 24U);
    func_00400090(arg0 / 25U);
    func_00400090(arg0 / 26U);
    func_00400090(arg0 / 27U);
    func_00400090(arg0 / 28U);
    func_00400090(arg0 / 29U);
    func_00400090(arg0 / 30U);
    func_00400090(arg0 / 31U);
    func_00400090(arg0 >> 5);
    func_00400090(arg0 / 33U);
    func_00400090(arg0 / 100U);
    func_00400090(arg0 / 255U);
    func_00400090(arg0 / 360U);
    func_00400090(arg0 / 1000U);
    func_00400090(arg0 / 10000U);
    func_00400090(arg0 / 100000U);
    func_00400090(arg0 / 1000000U);
    func_00400090(arg0 / 9934464U);
    func_00400090(arg0 / 89121024U);
    func_00400090(arg0 >> 0x1E);
    func_00400090(arg0 / 1073741825U);
    func_00400090(arg0 / 2147483646U);
    func_00400090(arg0 / 2147483647U);
    func_00400090(arg0 / 2147483648U);
    func_00400090(arg0 / 2147483649U);
    func_00400090(arg0 / -2U);
    func_00400090(arg0 / -1U);
}
