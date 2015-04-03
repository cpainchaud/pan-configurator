<?php


/*****************************************************************************
*
*	 more comments needed
*		
*	This script will load a PANOS config and create 15000 random rules
*
*****************************************************************************/
require_once("lib/shared.php");


$origfile = "sample-configs/pan-example1.xml";
$output = "output.xml";



$panc = new PANconf();
$panc->load_from_file($origfile);


// Did we find VSYS1 ?
$v = &$panc->findVirtualSystem('vsys1');
if( is_null($v) )
{
	derr("vsys1 was not found ? Exit\n");
}

print "\n***********************************************\n\n";

$newrules = Array();
$addresses = $v->addressStore->all();
$ac = count($addresses);
$ak = array_keys($addresses);

for( $i=0; $i < 15001; $i++ )
{
	$newrules[$i] = $v->securityRules->newSecurityRule('autogen-'.$i);
	$newrules[$i]->setName('autogen2-'.$i);
	if( $i%500 == 0 )
	{
		memory_and_gc("i=$i");
	}
	$r = rand(1,10);
	if( $r > 3 )
	{
		$r = rand(1,5);
		for($j =0; $j<$r; $j++ )
		{
			$addr = $addresses[$ak[rand(0,$ac-1)]];
			//print "adding '".$addr->name()."'\n";
			$newrules[$i]->source->add($addr);
			//$newrules[$i]->source->add('test');
		}
	}
}






print "\n***********************************************\n";
$v->display_statistics();

$panc->save_to_file($output);



memory_and_gc('end');





