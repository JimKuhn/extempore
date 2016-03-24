;; malloc zone structures
%mzone = type {i8*, i64, i64, i64, i8*, %mzone*}
%clsvar = type {i8*, i32, i8*, %clsvar*}

declare i32 @printf(i8* noalias nocapture, ...)
define i32 @llvm_printf(i8* noalias nocapture %format, ...) alwaysinline "thunk"
{
  %1 = musttail call i32 (i8*, ...) @printf(i8* %format, ...)
  ret i32 %1
}

declare i32 @sprintf(i8*, i8* noalias nocapture, ...)
define i32 @llvm_sprintf(i8* %string, i8* noalias nocapture %format, ...) alwaysinline "thunk"
{
  %1 = musttail call i32 (i8*, i8*, ...) @sprintf(i8* %string, i8* %format, ...)
  ret i32 %1
}

declare i32 @sscanf(i8*, i8* noalias nocapture, ...)
define i32 @llvm_sscanf(i8* %string, i8* noalias nocapture %format, ...) alwaysinline "thunk"
{
  %1 = musttail call i32 (i8*, i8*, ...) @sscanf(i8* %string, i8* %format, ...)
  ret i32 %1
}

declare i32 @fprintf(i8*, i8* noalias nocapture, ...)
define i32 @llvm_fprintf(i8* %file, i8* noalias nocapture %format, ...) alwaysinline "thunk"
{
  %1 = musttail call i32 (i8*, i8*, ...) @fprintf(i8* %file, i8* %format, ...)
  ret i32 %1
}

declare i32 @fscanf(i8*, i8* noalias nocapture, ...)
define i32 @llvm_fscanf(i8* %file, i8* noalias nocapture %format, ...) alwaysinline "thunk"
{
  %1 = musttail call i32 (i8*, i8*, ...) @fscanf(i8* %file, i8* %format, ...)
  ret i32 %1
}
