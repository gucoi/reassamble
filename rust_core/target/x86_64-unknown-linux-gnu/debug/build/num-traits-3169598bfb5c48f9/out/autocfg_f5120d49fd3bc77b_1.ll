; ModuleID = 'autocfg_f5120d49fd3bc77b_1.ad7aca763a705991-cgu.0'
source_filename = "autocfg_f5120d49fd3bc77b_1.ad7aca763a705991-cgu.0"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

$asan.module_ctor = comdat any

$asan.module_dtor = comdat any

$alloc_f93507f8ba4b5780b14b2c2584609be0.6134a76d7427f04669864f846e568592 = comdat any

$alloc_ef0a1f828f3393ef691f2705e817091c.6134a76d7427f04669864f846e568592 = comdat any

@alloc_f93507f8ba4b5780b14b2c2584609be0 = internal constant { [8 x i8], [24 x i8] } { [8 x i8] c"\00\00\00\00\00\00\F0?", [24 x i8] zeroinitializer }, comdat($alloc_f93507f8ba4b5780b14b2c2584609be0.6134a76d7427f04669864f846e568592), align 32
@alloc_ef0a1f828f3393ef691f2705e817091c = internal constant { [8 x i8], [24 x i8] } { [8 x i8] c"\00\00\00\00\00\00\00@", [24 x i8] zeroinitializer }, comdat($alloc_ef0a1f828f3393ef691f2705e817091c.6134a76d7427f04669864f846e568592), align 32
@___asan_gen_global = private unnamed_addr constant [39 x i8] c"alloc_f93507f8ba4b5780b14b2c2584609be0\00", align 1
@___asan_gen_module = private constant [50 x i8] c"autocfg_f5120d49fd3bc77b_1.ad7aca763a705991-cgu.0\00", align 1
@___asan_gen_global.1 = private unnamed_addr constant [39 x i8] c"alloc_ef0a1f828f3393ef691f2705e817091c\00", align 1
@__asan_global_alloc_f93507f8ba4b5780b14b2c2584609be0 = private global { i64, i64, i64, i64, i64, i64, i64, i64 } { i64 ptrtoint (ptr @anon.55ec300b615509bf6c374f859b6119d7.0 to i64), i64 8, i64 32, i64 ptrtoint (ptr @___asan_gen_global to i64), i64 ptrtoint (ptr @___asan_gen_module to i64), i64 0, i64 0, i64 -1 }, section "asan_globals", comdat($alloc_f93507f8ba4b5780b14b2c2584609be0.6134a76d7427f04669864f846e568592), !associated !0
@__asan_global_alloc_ef0a1f828f3393ef691f2705e817091c = private global { i64, i64, i64, i64, i64, i64, i64, i64 } { i64 ptrtoint (ptr @anon.55ec300b615509bf6c374f859b6119d7.1 to i64), i64 8, i64 32, i64 ptrtoint (ptr @___asan_gen_global.1 to i64), i64 ptrtoint (ptr @___asan_gen_module to i64), i64 0, i64 0, i64 -1 }, section "asan_globals", comdat($alloc_ef0a1f828f3393ef691f2705e817091c.6134a76d7427f04669864f846e568592), !associated !1
@llvm.compiler.used = appending global [4 x ptr] [ptr @alloc_f93507f8ba4b5780b14b2c2584609be0, ptr @alloc_ef0a1f828f3393ef691f2705e817091c, ptr @__asan_global_alloc_f93507f8ba4b5780b14b2c2584609be0, ptr @__asan_global_alloc_ef0a1f828f3393ef691f2705e817091c], section "llvm.metadata"
@___asan_globals_registered = common hidden global i64 0
@__start_asan_globals = extern_weak hidden global i64
@__stop_asan_globals = extern_weak hidden global i64
@llvm.used = appending global [2 x ptr] [ptr @asan.module_ctor, ptr @asan.module_dtor], section "llvm.metadata"
@llvm.global_ctors = appending global [1 x { i32, ptr, ptr }] [{ i32, ptr, ptr } { i32 1, ptr @asan.module_ctor, ptr @asan.module_ctor }]
@llvm.global_dtors = appending global [1 x { i32, ptr, ptr }] [{ i32, ptr, ptr } { i32 1, ptr @asan.module_dtor, ptr @asan.module_dtor }]

@anon.55ec300b615509bf6c374f859b6119d7.0 = private alias { [8 x i8], [24 x i8] }, ptr @alloc_f93507f8ba4b5780b14b2c2584609be0
@anon.55ec300b615509bf6c374f859b6119d7.1 = private alias { [8 x i8], [24 x i8] }, ptr @alloc_ef0a1f828f3393ef691f2705e817091c

; core::f64::<impl f64>::total_cmp
; Function Attrs: inlinehint nonlazybind sanitize_address uwtable
define internal i8 @"_ZN4core3f6421_$LT$impl$u20$f64$GT$9total_cmp17h842cd2cdc90a168bE"(ptr align 8 %self, ptr align 8 %other) unnamed_addr #0 {
start:
  %_6 = alloca [8 x i8], align 8
  %_3 = alloca [8 x i8], align 8
  call void @llvm.lifetime.start.p0(i64 8, ptr %_3)
  %0 = ptrtoint ptr %self to i64
  %1 = lshr i64 %0, 3
  %2 = add i64 %1, 2147450880
  %3 = inttoptr i64 %2 to ptr
  %4 = load i8, ptr %3, align 1
  %5 = icmp ne i8 %4, 0
  br i1 %5, label %6, label %7

6:                                                ; preds = %start
  call void @__asan_report_load8(i64 %0) #5
  unreachable

7:                                                ; preds = %start
  %_5 = load double, ptr %self, align 8
  %_4 = bitcast double %_5 to i64
  store i64 %_4, ptr %_3, align 8
  call void @llvm.lifetime.start.p0(i64 8, ptr %_6)
  %8 = ptrtoint ptr %other to i64
  %9 = lshr i64 %8, 3
  %10 = add i64 %9, 2147450880
  %11 = inttoptr i64 %10 to ptr
  %12 = load i8, ptr %11, align 1
  %13 = icmp ne i8 %12, 0
  br i1 %13, label %14, label %15

14:                                               ; preds = %7
  call void @__asan_report_load8(i64 %8) #5
  unreachable

15:                                               ; preds = %7
  %_8 = load double, ptr %other, align 8
  %_7 = bitcast double %_8 to i64
  store i64 %_7, ptr %_6, align 8
  %_13 = load i64, ptr %_3, align 8
  %_12 = ashr i64 %_13, 63
  %_10 = lshr i64 %_12, 1
  %16 = load i64, ptr %_3, align 8
  %17 = xor i64 %16, %_10
  store i64 %17, ptr %_3, align 8
  %_18 = load i64, ptr %_6, align 8
  %_17 = ashr i64 %_18, 63
  %_15 = lshr i64 %_17, 1
  %18 = load i64, ptr %_6, align 8
  %19 = xor i64 %18, %_15
  store i64 %19, ptr %_6, align 8
  %_19 = load i64, ptr %_3, align 8
  %_20 = load i64, ptr %_6, align 8
  %_0 = call i8 @llvm.scmp.i8.i64(i64 %_19, i64 %_20)
  call void @llvm.lifetime.end.p0(i64 8, ptr %_6)
  call void @llvm.lifetime.end.p0(i64 8, ptr %_3)
  ret i8 %_0
}

; autocfg_f5120d49fd3bc77b_1::probe
; Function Attrs: nonlazybind sanitize_address uwtable
define void @_ZN26autocfg_f5120d49fd3bc77b_15probe17h8b9796d600ec3df5E() unnamed_addr #1 {
start:
; call core::f64::<impl f64>::total_cmp
  %_1 = call i8 @"_ZN4core3f6421_$LT$impl$u20$f64$GT$9total_cmp17h842cd2cdc90a168bE"(ptr align 8 @alloc_f93507f8ba4b5780b14b2c2584609be0, ptr align 8 @alloc_ef0a1f828f3393ef691f2705e817091c)
  ret void
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare i8 @llvm.scmp.i8.i64(i64, i64) #2

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg, ptr nocapture) #3

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg, ptr nocapture) #3

declare void @__asan_report_load_n(i64, i64)

declare void @__asan_loadN(i64, i64)

declare void @__asan_report_load1(i64)

declare void @__asan_load1(i64)

declare void @__asan_report_load2(i64)

declare void @__asan_load2(i64)

declare void @__asan_report_load4(i64)

declare void @__asan_load4(i64)

declare void @__asan_report_load8(i64)

declare void @__asan_load8(i64)

declare void @__asan_report_load16(i64)

declare void @__asan_load16(i64)

declare void @__asan_report_store_n(i64, i64)

declare void @__asan_storeN(i64, i64)

declare void @__asan_report_store1(i64)

declare void @__asan_store1(i64)

declare void @__asan_report_store2(i64)

declare void @__asan_store2(i64)

declare void @__asan_report_store4(i64)

declare void @__asan_store4(i64)

declare void @__asan_report_store8(i64)

declare void @__asan_store8(i64)

declare void @__asan_report_store16(i64)

declare void @__asan_store16(i64)

declare void @__asan_report_exp_load_n(i64, i64, i32)

declare void @__asan_exp_loadN(i64, i64, i32)

declare void @__asan_report_exp_load1(i64, i32)

declare void @__asan_exp_load1(i64, i32)

declare void @__asan_report_exp_load2(i64, i32)

declare void @__asan_exp_load2(i64, i32)

declare void @__asan_report_exp_load4(i64, i32)

declare void @__asan_exp_load4(i64, i32)

declare void @__asan_report_exp_load8(i64, i32)

declare void @__asan_exp_load8(i64, i32)

declare void @__asan_report_exp_load16(i64, i32)

declare void @__asan_exp_load16(i64, i32)

declare void @__asan_report_exp_store_n(i64, i64, i32)

declare void @__asan_exp_storeN(i64, i64, i32)

declare void @__asan_report_exp_store1(i64, i32)

declare void @__asan_exp_store1(i64, i32)

declare void @__asan_report_exp_store2(i64, i32)

declare void @__asan_exp_store2(i64, i32)

declare void @__asan_report_exp_store4(i64, i32)

declare void @__asan_exp_store4(i64, i32)

declare void @__asan_report_exp_store8(i64, i32)

declare void @__asan_exp_store8(i64, i32)

declare void @__asan_report_exp_store16(i64, i32)

declare void @__asan_exp_store16(i64, i32)

declare ptr @__asan_memmove(ptr, ptr, i64)

declare ptr @__asan_memcpy(ptr, ptr, i64)

declare ptr @__asan_memset(ptr, i32, i64)

declare void @__asan_handle_no_return()

declare void @__sanitizer_ptr_cmp(i64, i64)

declare void @__sanitizer_ptr_sub(i64, i64)

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare i1 @llvm.amdgcn.is.shared(ptr nocapture) #2

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare i1 @llvm.amdgcn.is.private(ptr nocapture) #2

declare void @__asan_before_dynamic_init(i64)

declare void @__asan_after_dynamic_init()

declare void @__asan_register_globals(i64, i64)

declare void @__asan_unregister_globals(i64, i64)

declare void @__asan_register_image_globals(i64)

declare void @__asan_unregister_image_globals(i64)

declare void @__asan_register_elf_globals(i64, i64, i64)

declare void @__asan_unregister_elf_globals(i64, i64, i64)

declare void @__asan_init()

; Function Attrs: nounwind
define internal void @asan.module_ctor() #4 comdat {
  call void @__asan_init()
  call void @__asan_version_mismatch_check_v8()
  call void @__asan_register_elf_globals(i64 ptrtoint (ptr @___asan_globals_registered to i64), i64 ptrtoint (ptr @__start_asan_globals to i64), i64 ptrtoint (ptr @__stop_asan_globals to i64))
  ret void
}

declare void @__asan_version_mismatch_check_v8()

; Function Attrs: nounwind
define internal void @asan.module_dtor() #4 comdat {
  call void @__asan_unregister_elf_globals(i64 ptrtoint (ptr @___asan_globals_registered to i64), i64 ptrtoint (ptr @__start_asan_globals to i64), i64 ptrtoint (ptr @__stop_asan_globals to i64))
  ret void
}

attributes #0 = { inlinehint nonlazybind sanitize_address uwtable "target-cpu"="x86-64" }
attributes #1 = { nonlazybind sanitize_address uwtable "target-cpu"="x86-64" }
attributes #2 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #3 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #4 = { nounwind }
attributes #5 = { nomerge }

!llvm.module.flags = !{!2, !3, !4}
!llvm.ident = !{!5}

!0 = !{ptr @alloc_f93507f8ba4b5780b14b2c2584609be0}
!1 = !{ptr @alloc_ef0a1f828f3393ef691f2705e817091c}
!2 = !{i32 8, !"PIC Level", i32 2}
!3 = !{i32 2, !"RtLibUseGOT", i32 1}
!4 = !{i32 4, !"nosanitize_address", i32 1}
!5 = !{!"rustc version 1.89.0-nightly (6f6971078 2025-05-28)"}
