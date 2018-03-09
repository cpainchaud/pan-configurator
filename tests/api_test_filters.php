<?php

echo "\n*************************************************\n";
echo   "**************** FILTER TESTERS *****************\n\n";

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

$cli = "php ../utils/upload-config.php in=input/panorama-8.0.xml out=api://{$api_ip_address} loadAfterUpload injectUserAdmin2  2>&1";
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

//$api_ip_address = "192.168.55.208";

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

$totalFilterCount = 0;
$totalFilterWithCiCount = 0;

foreach( RQuery::$defaultFilters as $type => &$filtersByField )
{
    foreach($filtersByField as $fieldName => &$filtersByOperator )
    {
        foreach( $filtersByOperator['operators'] as $operator => &$filter )
        {
            $totalFilterCount++;

            if( !isset($filter['ci']) )
                continue;

            $totalFilterWithCiCount++;

            if( $operator == '>,<,=,!' )
                $operator = '<';

            echo "\n\n\n *** Processing filter: {$type} / ({$fieldName} {$operator})\n";

            $ci = &$filter['ci'];

            $filterString = str_replace('%PROP%',  "{$fieldName} {$operator}", $ci['fString']);


            if( $type == 'rule' )
                $util = '../utils/rules-edit.php';
            elseif( $type == 'address' )
                $util = '../utils/address-edit.php';
            elseif( $type == 'service' )
                $util = '../utils/service-edit.php';
            elseif( $type == 'tag' )
                $util = '../utils/tag-edit.php';
            elseif( $type == 'app' )
            {
                echo "******* SKIPPED for now *******\n";
                continue;
            }
            else
                derr('unsupported');

            $location = 'any';
            $output = '/dev/null';
            $ruletype = 'any';


            $cli = "php $util in=api://{$api_ip_address} location={$location} actions=display 'filter={$filterString}'";

            if( $type == 'rule' )
                $cli .= " ruletype={$ruletype}";

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
}

echo "\n*****  *****\n";
echo " - Processed {$totalFilterCount} filters\n";
echo " - Found {$totalFilterWithCiCount} that are CI enabled\n";

echo "\n";
echo "\n*********** FINISHED TESTING FILTERS ************\n";
echo   "*************************************************\n\n";




