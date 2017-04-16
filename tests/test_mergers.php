<?php

echo "\n*************************************************\n";
echo   "**************** MERGER TESTERS *****************\n\n";

require_once '../lib/panconfigurator.php';

PH::processCliArgs();

if( ini_get('safe_mode') ){
    derr("SAFE MODE IS ACTIVE");
}



function runCommand($bin, &$stream, $force = true, $command = '')
{
    $stream = '';

    $bin .= $force ? " 2>&1" : '';

    $descriptorSpec = array
    (
        0 => array('pipe', 'r'),
        1 => array('pipe', 'w'),
        2 => array('pipe', 'w'),
    );

    $pipes = Array();

    $process = proc_open($bin, $descriptorSpec, $pipes);

    if( $process !== FALSE )
    {
        fwrite($pipes[0], $command);
        fclose($pipes[0]);

        $stream = stream_get_contents($pipes[1]);
        fclose($pipes[1]);

        $stream += stream_get_contents($pipes[2]);
        fclose($pipes[2]);

        return proc_close($process);
    }
    else
        return -1;

}

#$totalFilterCount = 0;
#$totalFilterWithCiCount = 0;

$test_merger = array( 'address', 'service', 'addressgroup', 'servicegroup' );

foreach( $test_merger as $merger )
{
    $ci['input'] = 'input/panorama-8.0-merger.xml';

    echo "\n\n\n *** Processing merger: {$merger} \n";

    if( $merger == 'address' )
    {
        $util = '../utils/address-merger.php';
        #$dupalgorithm = 'SameIP4Mapping';
    }
    elseif( $merger == 'addressgroup' )
    {
        $util = '../utils/addressgroup-merger.php';
        $dupalgorithm = 'SameIP4Mapping';
    }
    elseif( $merger == 'service' )
    {
        $util = '../utils/service-merger.php';
        $dupalgorithm = 'SamePorts';
    }
    elseif( $merger == 'servicegroup' )
    {
        $util = '../utils/servicegroup-merger.php';
        $dupalgorithm = 'SamePortMapping';
    }

    else
        derr('unsupported');

    $location = 'testDG';
    $output = '/dev/null';

    $cli = "php $util in={$ci['input']} out={$output} location={$location} allowMergingWithUpperLevel";

    if( $merger != 'address' )
        $cli .= " DupAlgorithm={$dupalgorithm}";

    $cli .= ' 2>&1';

    echo " * Executing CLI: {$cli}\n";

    $output = Array();
    $retValue = 0;

    exec($cli, $output, $retValue);

    foreach($output as $line)
    {
        echo '   ##  '; echo $line; echo "\n";
    }

    if( $retValue != 0 )
        derr("CLI exit with error code '{$retValue}'");

    echo "\n";

}

echo "\n*****  *****\n";
#echo " - Processed {$totalFilterCount} filters\n";
#echo " - Found {$totalFilterWithCiCount} that are CI enabled\n";

echo "\n";
echo "\n*********** FINISHED TESTING MERGERS ************\n";
echo   "*************************************************\n\n";




