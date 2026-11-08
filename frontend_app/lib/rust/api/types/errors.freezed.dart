// GENERATED CODE - DO NOT MODIFY BY HAND
// coverage:ignore-file
// ignore_for_file: type=lint, type=warning, deprecated_member_use, deprecated_member_use_from_same_package
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'errors.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// GENERATED CODE - DO NOT MODIFY BY HAND
// dart format off
T _$identity<T>(T value) => value;
/// @nodoc
mixin _$SdkError {





@override
bool operator ==(Object other) {
    return identical(this, other) || (other.runtimeType == runtimeType&&other is SdkError);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
    return 'SdkError()';
}


}

/// @nodoc
class $SdkErrorCopyWith<$Res>  {
$SdkErrorCopyWith(SdkError _, $Res Function(SdkError) __);
}


/// Adds pattern-matching-related methods to [SdkError].
extension SdkErrorPatterns on SdkError {
/// A variant of `map` that fallback to returning `orElse`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( SdkError_Network value)?  network,TResult Function( SdkError_Internal value)?  internal,TResult Function( SdkError_Crypto value)?  crypto,TResult Function( SdkError_Server value)?  server,required TResult orElse(),}){
final _that = this;
switch (_that) {
case SdkError_Network() when network != null:
return network(_that);case SdkError_Internal() when internal != null:
return internal(_that);case SdkError_Crypto() when crypto != null:
return crypto(_that);case SdkError_Server() when server != null:
return server(_that);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// Callbacks receives the raw object, upcasted.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case final Subclass2 value:
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( SdkError_Network value)  network,required TResult Function( SdkError_Internal value)  internal,required TResult Function( SdkError_Crypto value)  crypto,required TResult Function( SdkError_Server value)  server,}){
final _that = this;
switch (_that) {
case SdkError_Network():
return network(_that);case SdkError_Internal():
return internal(_that);case SdkError_Crypto():
return crypto(_that);case SdkError_Server():
return server(_that);}
}
/// A variant of `map` that fallback to returning `null`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( SdkError_Network value)?  network,TResult? Function( SdkError_Internal value)?  internal,TResult? Function( SdkError_Crypto value)?  crypto,TResult? Function( SdkError_Server value)?  server,}){
final _that = this;
switch (_that) {
case SdkError_Network() when network != null:
return network(_that);case SdkError_Internal() when internal != null:
return internal(_that);case SdkError_Crypto() when crypto != null:
return crypto(_that);case SdkError_Server() when server != null:
return server(_that);case _:
  return null;

}
}
/// A variant of `when` that fallback to an `orElse` callback.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( String field0)?  network,TResult Function( String field0)?  internal,TResult Function( String field0)?  crypto,TResult Function( String code,  String text,  String traceId)?  server,required TResult orElse(),}) {final _that = this;
switch (_that) {
case SdkError_Network() when network != null:
return network(_that.field0);case SdkError_Internal() when internal != null:
return internal(_that.field0);case SdkError_Crypto() when crypto != null:
return crypto(_that.field0);case SdkError_Server() when server != null:
return server(_that.code,_that.text,_that.traceId);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// As opposed to `map`, this offers destructuring.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case Subclass2(:final field2):
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( String field0)  network,required TResult Function( String field0)  internal,required TResult Function( String field0)  crypto,required TResult Function( String code,  String text,  String traceId)  server,}) {final _that = this;
switch (_that) {
case SdkError_Network():
return network(_that.field0);case SdkError_Internal():
return internal(_that.field0);case SdkError_Crypto():
return crypto(_that.field0);case SdkError_Server():
return server(_that.code,_that.text,_that.traceId);}
}
/// A variant of `when` that fallback to returning `null`
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( String field0)?  network,TResult? Function( String field0)?  internal,TResult? Function( String field0)?  crypto,TResult? Function( String code,  String text,  String traceId)?  server,}) {final _that = this;
switch (_that) {
case SdkError_Network() when network != null:
return network(_that.field0);case SdkError_Internal() when internal != null:
return internal(_that.field0);case SdkError_Crypto() when crypto != null:
return crypto(_that.field0);case SdkError_Server() when server != null:
return server(_that.code,_that.text,_that.traceId);case _:
  return null;

}
}

}

/// @nodoc


class SdkError_Network extends SdkError {
  const SdkError_Network(this.field0): super._();
  

 final  String field0;

/// Create a copy of SdkError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$SdkError_NetworkCopyWith<SdkError_Network> get copyWith => _$SdkError_NetworkCopyWithImpl<SdkError_Network>(this, _$identity);



@override
bool operator ==(Object other) {
    return identical(this, other) || (other.runtimeType == runtimeType&&other is SdkError_Network&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode {
    return Object.hash(runtimeType,field0);
}

@override
String toString() {
    return 'SdkError.network(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $SdkError_NetworkCopyWith<$Res> implements $SdkErrorCopyWith<$Res> {
  factory $SdkError_NetworkCopyWith(SdkError_Network value, $Res Function(SdkError_Network) _then) = _$SdkError_NetworkCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$SdkError_NetworkCopyWithImpl<$Res>
    implements $SdkError_NetworkCopyWith<$Res> {
  _$SdkError_NetworkCopyWithImpl(this._self, this._then);

  final SdkError_Network _self;
  final $Res Function(SdkError_Network) _then;

/// Create a copy of SdkError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(SdkError_Network(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class SdkError_Internal extends SdkError {
  const SdkError_Internal(this.field0): super._();
  

 final  String field0;

/// Create a copy of SdkError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$SdkError_InternalCopyWith<SdkError_Internal> get copyWith => _$SdkError_InternalCopyWithImpl<SdkError_Internal>(this, _$identity);



@override
bool operator ==(Object other) {
    return identical(this, other) || (other.runtimeType == runtimeType&&other is SdkError_Internal&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode {
    return Object.hash(runtimeType,field0);
}

@override
String toString() {
    return 'SdkError.internal(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $SdkError_InternalCopyWith<$Res> implements $SdkErrorCopyWith<$Res> {
  factory $SdkError_InternalCopyWith(SdkError_Internal value, $Res Function(SdkError_Internal) _then) = _$SdkError_InternalCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$SdkError_InternalCopyWithImpl<$Res>
    implements $SdkError_InternalCopyWith<$Res> {
  _$SdkError_InternalCopyWithImpl(this._self, this._then);

  final SdkError_Internal _self;
  final $Res Function(SdkError_Internal) _then;

/// Create a copy of SdkError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(SdkError_Internal(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class SdkError_Crypto extends SdkError {
  const SdkError_Crypto(this.field0): super._();
  

 final  String field0;

/// Create a copy of SdkError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$SdkError_CryptoCopyWith<SdkError_Crypto> get copyWith => _$SdkError_CryptoCopyWithImpl<SdkError_Crypto>(this, _$identity);



@override
bool operator ==(Object other) {
    return identical(this, other) || (other.runtimeType == runtimeType&&other is SdkError_Crypto&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode {
    return Object.hash(runtimeType,field0);
}

@override
String toString() {
    return 'SdkError.crypto(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $SdkError_CryptoCopyWith<$Res> implements $SdkErrorCopyWith<$Res> {
  factory $SdkError_CryptoCopyWith(SdkError_Crypto value, $Res Function(SdkError_Crypto) _then) = _$SdkError_CryptoCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$SdkError_CryptoCopyWithImpl<$Res>
    implements $SdkError_CryptoCopyWith<$Res> {
  _$SdkError_CryptoCopyWithImpl(this._self, this._then);

  final SdkError_Crypto _self;
  final $Res Function(SdkError_Crypto) _then;

/// Create a copy of SdkError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(SdkError_Crypto(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class SdkError_Server extends SdkError {
  const SdkError_Server({required this.code, required this.text, required this.traceId}): super._();
  

 final  String code;
 final  String text;
 final  String traceId;

/// Create a copy of SdkError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$SdkError_ServerCopyWith<SdkError_Server> get copyWith => _$SdkError_ServerCopyWithImpl<SdkError_Server>(this, _$identity);



@override
bool operator ==(Object other) {
    return identical(this, other) || (other.runtimeType == runtimeType&&other is SdkError_Server&&(identical(other.code, code) || other.code == code)&&(identical(other.text, text) || other.text == text)&&(identical(other.traceId, traceId) || other.traceId == traceId));
}


@override
int get hashCode {
    return Object.hash(runtimeType,code,text,traceId);
}

@override
String toString() {
    return 'SdkError.server(code: $code, text: $text, traceId: $traceId)';
}


}

/// @nodoc
abstract mixin class $SdkError_ServerCopyWith<$Res> implements $SdkErrorCopyWith<$Res> {
  factory $SdkError_ServerCopyWith(SdkError_Server value, $Res Function(SdkError_Server) _then) = _$SdkError_ServerCopyWithImpl;
@useResult
$Res call({
 String code, String text, String traceId
});




}
/// @nodoc
class _$SdkError_ServerCopyWithImpl<$Res>
    implements $SdkError_ServerCopyWith<$Res> {
  _$SdkError_ServerCopyWithImpl(this._self, this._then);

  final SdkError_Server _self;
  final $Res Function(SdkError_Server) _then;

/// Create a copy of SdkError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? code = null,Object? text = null,Object? traceId = null,}) {
  return _then(SdkError_Server(
code: null == code ? _self.code : code // ignore: cast_nullable_to_non_nullable
as String,text: null == text ? _self.text : text // ignore: cast_nullable_to_non_nullable
as String,traceId: null == traceId ? _self.traceId : traceId // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

// dart format on
