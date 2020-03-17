# pdi-strong-encryption-plugin
Kettle plugin that provides support for a stronger password encryption based on the RSA (Rivest–Shamir–Adleman) algorithm and that can be extended to use other asymmetric encryption algorithms.

Building
--------
It's a maven build, so `mvn clean package` is a typical default for a local build.

Pre-requisites
---------------
JDK 8 in your path.
Maven 3.3.9 in your path.

Keys generation
---------------
Key pair generation is as simple as running the following command `java -cp pdi-strong-encryption-plugin-1.0.0.jar com.erkatta.pentaho.encryption.util.KeyPairGenerator`. It will generate two files (public.key and private.key) in the current directory.

Usage
-----
Place the pdi-strong-encryption-plugin-1.0.0.jar in the plugins folder of your Penthao Data Integration installation (i.e. /data-integration/plugins) and then set the following parameters in your kettle.properties file:

KETTLE_PASSWORD_ENCODER_PLUGIN=SPE (mandatory)
KETTLE_STRONG_PASSWORD_ENCORED_PUBKEY_PATH=/path_to_the_public_key_folder/ (optional, default ./)
KETTLE_STRONG_PASSWORD_ENCORED_PRIVKEY_PATH=/path_to_the_private_key_folder/ (optional, default ./)
KETTLE_STRONG_PASSWORD_ENCORED_PUBKEY_FILENAME=public_key_filename (optional, default public.key)
KETTLE_STRONG_PASSWORD_ENCORED_PRIVKEY_FILENAME=private_key_filename (optional, default private.key)

Generation of encrypted password can be performed using the encr.sh script present in the Penthao Data Integration installation folder just adding the following lines at the top:

`PENTAHO_DI_JAVA_OPTIONS="-DKETTLE_PASSWORD_ENCODER_PLUGIN=SPE [Other properties listed above prefixed with -D]"
export PENTAHO_DI_JAVA_OPTIONS`

Once you've added those line simply execute `./encr.sh -kettle yourpassword`

License
-------
Licensed under the GNU Lesser General Public License v2.1. See LICENSE.txt for more information.
