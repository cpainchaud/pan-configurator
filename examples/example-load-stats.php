<?php

// load 'PAN Configurator' library
require "lib/shared.php";

/***************************************************************

 

****************************************************************/


// input and ouput xml files
$inputfile = 'sample-configs/panorama-example.xml';
$outputfile = 'output.xml';


// Create a new PanoramaConf object
$p = new PanoramaConf();
// and load it from a XML file
$p->load_from_file($inputfile);

print "\n***********************************************\n\n";




// display some statiscs for debug and exit program!
print "\n\n***********************************************\n";
$p->display_statistics();


