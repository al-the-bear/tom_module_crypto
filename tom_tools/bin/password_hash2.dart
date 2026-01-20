import 'dart:math';
import 'dart:typed_data';
import 'package:pointycastle/export.dart';

Future<void> main( List<String> args ) async {

  var hashSpec = "Argon2;2i,13,4,65536,4,128";

  var password = Uint8List.fromList('pass123457'.codeUnits);

  var securan = Random.secure();
  var salt = Uint8List(16);
  for( int i = 0; i < salt.length; i++ ) {
    salt[i] = securan.nextInt(255);
  }

  var algo = buildKeyDerivator(hashSpec, toHexString(salt) );

  var result = Uint8List(algo.keySize);
  algo.deriveKey(password, 0, result, 0);

  var safedSaltHash = "${toHexString(salt)}\$${toHexString(result)}";

  print("Hash is $safedSaltHash");

  var [safedSalt,safedPassword] = safedSaltHash.split("\$");

  var password2 = Uint8List.fromList('pass123457'.codeUnits);

  // ignore: unused_local_variable
  var algo2 = Argon2BytesGenerator();

  var params2 = Argon2Parameters(
      Argon2Parameters.ARGON2_i,
      toUint8List(safedSalt),
      version: Argon2Parameters.ARGON2_VERSION_13,
      iterations: 4,
      memoryPowerOf2: 16,
      lanes: 4,
      desiredKeyLength: 128);

  algo.init(params2);

  var result2 = Uint8List(128);
  algo.deriveKey(password2, 0, result2, 0);

  var safedSaltHash2 = "$safedSalt\$${toHexString(result2)}";

  print("Test helper: $safedSalt ${toHexString(toUint8List(safedSalt))}");
  print("Hash is $safedSaltHash2 it's a match: ${safedSaltHash2==safedSaltHash}");

  var( spec, saltExtract ) = parameterString(params2);
  print( "$spec $saltExtract");
  var( spec2, saltExtract2 ) = parameterString(params2);
  print( "$spec2 $saltExtract2");
  var( spec3, saltExtract3 ) = parameterString(makeArgonParams(spec, saltExtract));
  print( "$spec3 $saltExtract3");

}

KeyDerivator buildKeyDerivator( String specification, String saltHexString ) {
  var specParts = specification.split(";");
  if( specParts[0] == "Argon2" ) {
    var params = makeArgonParams(specParts[1], saltHexString);
    KeyDerivator result = Argon2BytesGenerator();
    result.init(params);
    return result;
  }
  throw Exception("Invalid key derivator spec $specification");
}

Argon2Parameters makeArgonParams( String specification, String saltHexString ) {

  var saltBytes = toUint8List(saltHexString);

  var parts = specification.split(",");

  var algoType = 0;
  var algoVersion = 0;
  var iterations = 0;
  var memory = 0;
  var lanes = 0;
  var keyLength = 0;

  if( parts[0] == "2i") {
    algoType = Argon2Parameters.ARGON2_i;
  } else if( parts[0] == "2d") {
    algoType = Argon2Parameters.ARGON2_d;
  } else if( parts[0] == "2id") {
    algoType = Argon2Parameters.ARGON2_id;
  }

  if( parts[1] == "13") {
    algoVersion = Argon2Parameters.ARGON2_VERSION_13;
  } else if( parts[1] == "10") {
    algoVersion = Argon2Parameters.ARGON2_VERSION_10;
  }

  iterations = int.parse(parts[2]);
  memory = int.parse(parts[3]);
  lanes = int.parse(parts[4]);
  keyLength = int.parse(parts[5]);

  return Argon2Parameters(algoType, saltBytes,
      version: algoVersion,
      iterations: iterations,
      memory: memory,
      lanes: lanes,
      desiredKeyLength: keyLength);
}

(String, String) parameterString( Argon2Parameters params ) {
  String result = "";
  if( params.type == Argon2Parameters.ARGON2_i ) {
    result += "2i";
  }
  if( params.version == Argon2Parameters.ARGON2_VERSION_13 ) {
    result += ",13";
  }
  result += ",${params.iterations}";
  result += ",${params.memory}";
  result += ",${params.lanes}";
  result += ",${params.desiredKeyLength}";
  String result2 = toHexString(params.salt);
  return (result, result2);
}

String toHexString( Uint8List list ) {
  StringBuffer b = StringBuffer();
  for( var byte in list ) {
    if( byte < 16 ) {
      b.write("0${byte.toRadixString(16)}");
    }else{
      b.write(byte.toRadixString(16));
    }
  }
  var result = b.toString();
  return result;
}

Uint8List toUint8List( String hexString ) {
  var result = Uint8List(hexString.length~/2);
  for(int i = 0; i < result.length; i++ ) {
    result[i] = int.parse(hexString.substring(i*2,i*2+2), radix: 16);
  }
  return result;
}