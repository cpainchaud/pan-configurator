<?php

echo "\n***********************************************\n";
echo   "*********** ".basename(__FILE__)." UTILITY **************\n\n";

set_include_path( dirname(__FILE__).'/../'. PATH_SEPARATOR . get_include_path() );
require_once("lib/panconfigurator.php");
require_once(dirname(__FILE__).'/common/misc.php');

$supportedArguments = Array();
$supportedArguments[] = Array('niceName' => 'Action', 'shortHelp' => 'type of action you want to perform against API', 'argDesc' => 'register|unregister|fakeregister');
$supportedArguments[] = Array('niceName' => 'in', 'shortHelp' => 'the target PANOS device ie: in=api://1.2.3.4', 'argDesc' => 'api://[hostname or IP]');
$supportedArguments[] = Array('niceName' => 'Location', 'shortHelp' => 'defines the VSYS target of the UserID request', 'argDesc' => 'vsys1[,vsys2,...]');
$supportedArguments[] = Array('niceName' => 'records', 'shortHelp' => 'list of userid records to register/unregister in API', 'argDesc' => '10.0.0.1,domain\user2/10.2.3.4,domain\user3');
$supportedArguments[] = Array('niceName' => 'recordFile', 'shortHelp' => 'use a text file rather than CLI to input UserID records', 'argDesc' => 'users.txt');
$supportedArguments[] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments[] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');

$usageMsg = PH::boldText('USAGE EXAMPLES: ')."\n - php ".basename(__FILE__)." in=api://1.2.3.4 action=register location=vsys1 records=10.0.0.1,domain\\user2/10.2.3.4,domain\\user3"
                                            ."\n - php ".basename(__FILE__)." in=api://1.2.3.4 action=register location=vsys1 recordsFile=users.txt";

prepareSupportedArgumentsArray($supportedArguments);

PH::processCliArgs();

// check that only supported arguments were provided
foreach ( PH::$args as $index => &$arg )
{
    if( !isset($supportedArguments[$index]) )
        display_error_usage_exit("unsupported argument provided: '$index'");
}

if( isset(PH::$args['help']) )
    display_usage_and_exit();


if( !isset(PH::$args['in']) )
    display_error_usage_exit(' "in=" argument is missing');


if( isset(PH::$args['debugapi'])  )
{
    $debugAPI = true;
}

//
// What kind of config input do we have.
//     File or API ?
//
// <editor-fold desc="  ****  input method validation and PANOS vs Panorama auto-detect  ****" defaultstate="collapsed" >
$configInput = PH::processIOMethod(PH::$args['in'], true);
$xmlDoc = null;

if( $configInput['status'] == 'fail' )
{
    fwrite(STDERR, "\n\n**ERROR** " . $configInput['msg'] . "\n\n");exit(1);
}

/** @var PanAPIConnector $connector */
$connector = null;

if( $configInput['type'] == 'file' )
{
    derr("Only API method is supported for input, please fix your 'in' argument");

}
elseif ( $configInput['type'] == 'api'  )
{
    $connector = $configInput['connector'];
    if($debugAPI)
        $connector->setShowApiCalls(true);
}
else
    derr('method not supported yet');
// </editor-fold>

echo " - Connected to API at {$connector->apihost} / {$connector->info_hostname}\n";
echo " - PANOS version: {$connector->info_PANOS_version}\n";
echo " - PANOS model: {$connector->info_model}\n";
echo "\n";


if( !isset(PH::$args['action']) )
    display_error_usage_exit("no 'action' was defined");

$location = 'vsys1';
if( !isset(PH::$args['location']) )
    echo " - no 'location' was provided, using default VSYS1\n";
else
{
    $location = PH::$args['location'];
    echo " - location '{$location}' was provided\n";
}



$action = strtolower(PH::$args['action']);

if( $action == 'register' || $action == 'unregister' )
{
    echo " - action is '$action'\n";
    $records = Array();

    if( isset(PH::$args['records']) )
    {
        echo " - a list of 'records' was provided on CLI, now parsing it...";
        $explode = explode('/',PH::$args['records']);
        foreach($explode as $record)
        {
            $lrecord = explode(',', $record);
            if( count($lrecord) != 2 )
                display_error_usage_exit("the following record does not have the right syntax: '{$record}'");
            $username = trim($lrecord[1]);
            $ipaddress = trim($lrecord[0]);

            if( strlen($username) < 1 )
                display_error_usage_exit("blank username in record '{$record}'");

            if( strlen($ipaddress) < 1 )
                display_error_usage_exit("blank IP in record '{$record}'");

            if( isset($records[$ipaddress]) && $records[$ipaddress] != $username )
                display_error_usage_exit("record '{$ipaddress}\\{$username}' conflicts with '{$ipaddress}\\{$records[$ipaddress]}'");

            if( !filter_var($ipaddress, FILTER_VALIDATE_IP) )
                display_error_usage_exit("IP address '{$ipaddress}' is not valid in record '{$record}'");

            $records[$ipaddress] = $username;
        }

        echo "OK!\n";
    }
    elseif( isset(PH::$args['recordfile']) )
    {
        echo " - record file was provided, now parsing it...";

        $explode = file_get_contents(PH::$args['recordfile']);
        $explode = explode("\n",$explode);

        foreach($explode as $record)
        {
            if( strlen(trim($record)) < 1 )
                continue; // this is an empty line

            $lrecord = explode(',', $record);
            if( count($lrecord) != 2 )
                display_error_usage_exit("the following record does not have the right syntax: '{$record}'");
            $username = trim($lrecord[1]);
            $ipaddress = trim($lrecord[0]);

            if( strlen($username) < 1 )
                display_error_usage_exit("blank username in record '{$record}'");

            if( strlen($ipaddress) < 1 )
                display_error_usage_exit("blank IP in record '{$record}'");

            if( isset($records[$ipaddress]) && $records[$ipaddress] != $username )
                display_error_usage_exit("record '{$ipaddress}\\{$username}' conflicts with '{$ipaddress}\\{$records[$ipaddress]}'");

            if( !filter_var($ipaddress, FILTER_VALIDATE_IP) )
                display_error_usage_exit("IP address '{$ipaddress}' is not valid in record '{$record}'");

            $records[$ipaddress] = $username;
        }

        echo "OK!\n";
    }
    else
        derr("you need to provide 'records' or 'recordfile' argument");

    $count = count($records);
    echo " - found {$count} records:\n";
    foreach($records as $ip => $user)
    {
        echo "   - ".str_pad($ip,16)." / {$user}\n";
    }

    echo " - now sending records to API ... ";
    if( $action =='register' )
        $connector->userIDLogin(array_keys($records), $records, $location);
    else
        $connector->userIDLogout(array_keys($records), $records, $location);

    echo "OK!\n";

}
elseif( $action == 'fakeregister' )
{
    $numberOfIPs = 500;
    $userPrefix = 'acme\\Bob_';
    $startingIP = ip2long('10.0.0.0');

    $records = Array();


    echo "  - Generating {$numberOfIPs} fake records starting at IP ".long2ip($startingIP)."... ";
    for($i=1; $i<= $numberOfIPs; $i++)
    {
        $records[long2ip($startingIP+$i)] = $userPrefix.$i;
    }
    echo "OK!\n";


    echo " - now sending records to API ... ";
    $connector->userIDLogin(array_keys($records), $records, $location);
    echo "OK!\n";

}
else
    derr("action '{$action}' is not supported");





echo "\n\n***********************************************\n";
echo "************* END OF SCRIPT ".basename(__FILE__)." ************\n";
echo "***********************************************\n\n";

