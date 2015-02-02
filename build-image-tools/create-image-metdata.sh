#!/bin/bash

#
# Author: I.Baldine <ibaldin@renci.org> Copyright UNC-Chapel Hill/RENCI 2012
#
# The purpose of this script is to simplify the creation of image descriptor XML
# files to be used with ImageProxy component of ExoGENI. 
# Given a filesystem file and optionally a kernel and a ramdisk and an http:// prefix
# where they can be found it
# 1) Verifies that the files are reachable via http
# 2) Constructs the XML image descriptor file (including computing the SHA-1 hashes)
# 3) Prints out the URL and the SHA-1 hash of the image descriptor file that can
# then be used with ExoGENI slices
#
# This script requires curl to be installed and getopts to be supported (relatively new
# version of Bash). 

# The following command line options are supported:
# -u: the HTTP URL prefix where image components can be found [mandatory]
# -n: the name of the XML image descriptor file that will be created [mandatory]
# -z: gzipped file system image (sparse or non-sparse)
# -f: regular (sparse or non-sparse, uncompressed) filesystem image. Either -z or -f must be specified
# -k: kernel file [optional]
# -r: ramdisk file [optional]

# Place the prepared image files on the host running HTTP server,
# execute the script from the directory where the image files are located.

# User-editable parameters:

# Where is curl?
CURL=/usr/bin/curl
SHASUM=/usr/bin/sha1sum

#
# DO NOT EDIT BELOW
#
IMAGESET=false
KERNELSET=false
RAMDISKSET=false
URLSET=false
XMLFILENAMESET=false
VERSION=""

function executable {
	fil=$1

	if [ ! -x $fil ]; then
		echo "ERROR: cannot locate $fil executable. Please install and edit the top portion of the script (if necessary)"
		exit 1
	fi
}

function shasum {
	fil=$1

	echo `$SHASUM $fil | awk '{print $1}' `
}


function getfile {
        url=$1

        #echo -n "Getting file over HTTP of $url"
	FILENAME=`$CURL -I $url 2> /dev/null | grep filename | awk -F"\"" '{print $2}'`
        HTTPVAL=`$CURL -I $url 2> /dev/null | grep HTTP | awk '{print $2}'`
        if [ "$HTTPVAL" != "200" ]; then
                echo
                echo "ERROR: unable to retrieve $url. HTTP code $HTTPVAL. Typical values: 403 - Forbidden, 404 - Not Found"
                exit 1
        fi
 	#echo " [OK]"
		
	$CURL $url -o ${FILENAME}  #&>/dev/null

	echo ${FILENAME}
}
	

function reachable { 
	url=$1
	fil=$2

	echo -n "Testing file presence of $fil"
	if [ ! -e ./$fil ]; then
		echo
		echo "ERROR: unable to locate file $fil. You must execute this script from the directories where the files reside. "
		exit 1
	fi
	echo " [OK]"

	echo -n "Testing reachability over HTTP of $fil"
	HTTPVAL=`$CURL -I $url/$fil 2> /dev/null | grep HTTP | awk '{print $2}'`
	if [ "$HTTPVAL" != "200" ]; then
		echo
		echo "ERROR: unable to retrieve $url/$fil. HTTP code $HTTPVAL. Typical values: 403 - Forbidden, 404 - Not Found"
		exit 1
	fi
	echo " [OK]"
}

while getopts ":hz:f:k:r:u:n:" opt; do
  case $opt in
    n)
	XMLFILENAME=$OPTARG
	XMLFILENAMESET=true
	;;
    z)
	ZFILESYSTEM_URL=$OPTARG
	IMAGESET=true
	;;
    f)	
	FILESYSTEM_URL=$OPTARG
	IMAGESET=true
	;;
    k)
	KERNEL_URL=$OPTARG
	KERNELSET=true
	;;
    r)	
	RAMDISK_URL=$OPTARG
	RAMDISKSET=true
	;;
    h)
	cat << 'EndOfHelp'

The purpose of this script is to simplify the creation of image descriptor XML
files to be used with ImageProxy component of ExoGENI. 
https://code.renci.org/gf/project/networkedclouds/wiki/?pagename=ImageProxyMetaFile

Given a filesystem file and optionally a kernel and a ramdisk and an http:// prefix
where they can be found it
1) Verifies that the files are reachable via http
2) Constructs the XML image descriptor file (including computing the SHA-1 hashes)
3) Prints out the URL and the SHA-1 hash of the image descriptor file that can
then be used with ExoGENI slices

This script requires curl to be installed and getopts to be supported (relatively new
version of Bash). 

The following command line options are supported:
-u: the HTTP URL prefix where image components can be found [mandatory]
-n: the name of the XML image descriptor file that will be created [mandatory]
-z: gzipped file system image (sparse or non-sparse)
-f: uncompressed (sparse or non-sparse) filesystem image. Either -z or -f must be specified
-k: kernel file [optional]
-r: ramdisk file [optional]

Place the prepared image files on the host running HTTP server,
execute the script from the directory where the image files are located.
EndOfHelp
	exit 0
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done

executable $CURL
executable $SHASUM

if ( ! $IMAGESET ); then
	echo "ERROR: you must specify at least -z or -f"
	exit 1
fi

if ( ! $XMLFILENAMESET ); then
	echo "ERROR: you must specify the name of the XML image description file that will be created by this script"
	exit 1
fi

# test reachability and files
if [ "$ZFILESYSTEM_URL" != "" ]; then
	echo getting $ZFILESYSTEM_URL
        FSNAME=$(getfile $ZFILESYSTEM_URL)
	FSSUM=$(shasum $FSNAME)
	FSTAG="ZFILESYSTEM"
	FSURL="$ZFILESYSTEM_URL"
fi

if [ "$FILESYSTEM_URL" != "" ]; then
	echo getting $FILESYSTEM_URL
        FSNAME=$(getfile $FILESYSTEM_URL)
        FSSUM=$(shasum $FSNAME)
	FSTAG="FILESYSTEM"
	FSURL="$FILESYSTEM_URL"
fi

if ( $KERNELSET ); then
	echo getting $KERNEL_URL
        KERNELNAME=$(getfile $KERNEL_URL)
        KERNELSUM=$(shasum $KERNELNAME)
	KERNELURL="$KERNEL_URL"
fi

if ( $RAMDISKSET ); then
	echo getting $RAMDISK_URL
        RAMDISKNAME=$(getfile $RAMDISK_URL)
        RAMDISKSUM=$(shasum $RAMDISKNAME)
	RAMDISKURL="$RAMDISK_URL"
fi

echo "Creating XML image descriptor file $XMLFILENAME" 

(
cat << EOF
<images> 	     
     <image>
          <type>$FSTAG</type>
          <signature>$FSSUM</signature>
          <url>$FSURL</url>
     </image>
EOF
) > $XMLFILENAME
if ( $KERNELSET ); then
(
cat << EOF
     <image>
          <type>KERNEL</type>
          <signature>$KERNELSUM</signature>
          <url>$KERNELURL</url>
     </image>
EOF
) >> $XMLFILENAME
fi
if ( $RAMDISKSET ); then
(
cat << EOF
    <image>
          <type>RAMDISK</type>
          <signature>$RAMDISKSUM</signature>
          <url>$RAMDISKURL</url>
     </image>
EOF
) >> $XMLFILENAME
fi

(
cat << EOF
</images>
EOF
) >> $XMLFILENAME 


#reachable $URL $XMLFILENAME

XMLHASH=`shasum $XMLFILENAME`
echo
echo
echo Metadata:
echo
echo
cat $XMLFILENAME
echo
echo
echo "XML image descriptor file SHA1 hash is: $XMLHASH"
echo "XML image descriptor file is: $XMLFILENAME"
