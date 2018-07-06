<?php


/*****************************************************************************
*
*	 more comments needed
*		
*	This script will load a PANOS config and create 1500 random rules
*
*****************************************************************************/
require_once("../lib/panconfigurator.php");


$origfile = "sample-configs/panos-example-2.xml";
$output = "output.xml";



$panc = new PANconf();
$panc->load_from_file($origfile);


// Did we find VSYS1 ?
$v = &$panc->findVirtualSystem('vsys1');
if( $v === null )
{
	derr("vsys1 was not found ? Exit\n");
}

print "\n***********************************************\n\n";


$v->securityRules->removeAll();

/** @var SecurityRule[] $newRules */
$newRules = Array();
$addresses = $v->addressStore->all();
$ac = count($addresses);
$ak = array_keys($addresses);

for( $i=0; $i < 1500; $i++ )
{
	$newRules[$i] = $v->securityRules->newSecurityRule('autogen-'.$i);

	$r = rand(1,10);
	if( $r > 3 )
	{
		$r = rand(1,5);
		for($j =0; $j<$r; $j++ )
		{
			$addr = $addresses[$ak[rand(0,$ac-1)]];
			$newRules[$i]->source->addObject($addr);
		}
	}

    $r = rand(1,10);
    if( $r > 3 )
    {
        $r = rand(1,5);
        for($j =0; $j<$r; $j++ )
        {
            $addr = $addresses[$ak[rand(0,$ac-1)]];
            $newRules[$i]->destination->addObject($addr);
        }
    }
}






print "\n***********************************************\n";
$v->display_statistics();

$panc->save_to_file($output);



memory_and_gc('end');





