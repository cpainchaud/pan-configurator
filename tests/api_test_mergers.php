<?php

echo "\n*************************************************\n";
echo   "**************** MERGER TESTERS *****************\n\n";

require_once '../lib/panconfigurator.php';

PH::processCliArgs();

if( ini_get('safe_mode') ){
    derr("SAFE MODE IS ACTIVE");
}

########################################################################################################################
########################################################################################################################
if( ! isset(PH::$args['in']) )
    display_error_usage_exit('"in" is missing from arguments');
$configInput = PH::$args['in'];
if( !is_string($configInput) || strlen($configInput) < 1 )
    display_error_usage_exit('"in" argument is not a valid string');

if( strpos( $configInput, "api://" ) !== false )
    $api_ip_address = substr( $configInput, 6 );
else
    derr( '"in" argument must be of type API [in=api://192.168.55.208]' );

$cli = "php ../utils/upload-config.php in=input/panorama-8.0-merger.xml out=api://{$api_ip_address} loadAfterUpload injectUserAdmin2  2>&1";
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

function display_error_usage_exit($msg)
{
    fwrite(STDERR, PH::boldText("\n**ERROR** ").$msg."\n\n");
    #display_usage_and_exit(true);
}
########################################################################################################################
########################################################################################################################


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

    $dupalgorithm_array = array();
    if( $merger == 'address' )
    {
        $util = '../utils/address-merger.php';
        $dupalgorithm_array[] = '';
    }
    elseif( $merger == 'addressgroup' )
    {
        $util = '../utils/addressgroup-merger.php';
        $dupalgorithm_array[] = 'SameMembers';
        $dupalgorithm_array[] = 'SameIP4Mapping';
        $dupalgorithm_array[] = 'Whereused';

    }
    elseif( $merger == 'service' )
    {
        $util = '../utils/service-merger.php';
        $dupalgorithm_array[] = 'SamePorts';
        $dupalgorithm_array[] = 'Whereused';
    }
    elseif( $merger == 'servicegroup' )
    {
        $util = '../utils/servicegroup-merger.php';
        $dupalgorithm_array[] = 'SameMembers';
        $dupalgorithm_array[] = 'SamePortMapping';
        $dupalgorithm_array[] = 'Whereused';
    }

    else
        derr('unsupported');

    foreach( $dupalgorithm_array as $dupalgorithm)
    {
        $location = 'testDG';
        $output = '/dev/null';

        $cli = "php $util in=api://{$api_ip_address} location={$location} allowMergingWithUpperLevel";

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


}

echo "\n*****  *****\n";
#echo " - Processed {$totalFilterCount} filters\n";
#echo " - Found {$totalFilterWithCiCount} that are CI enabled\n";

echo "\n";
echo "\n*********** FINISHED TESTING MERGERS ************\n";
echo   "*************************************************\n\n";




