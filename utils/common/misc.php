<?php


function display_error_usage_exit($msg)
{
    fwrite(STDERR, PH::boldText("\n**ERROR** ").$msg."\n\n");
    display_usage_and_exit(true);
}

function display_usage_and_exit($shortMessage = false)
{
    global $supportedArguments;
    global $usageMsg;

    echo $usageMsg.
        "\n\n";

    if( !$shortMessage )
    {
        echo PH::boldText("\nListing available arguments\n\n");

        ksort($supportedArguments);
        foreach( $supportedArguments as &$arg )
        {
            echo " - ".PH::boldText($arg['niceName']);
            if( isset( $arg['argDesc']))
                echo '='.$arg['argDesc'];
            //."=";
            if( isset($arg['shortHelp']))
                echo "\n     ".$arg['shortHelp'];
            echo "\n\n";
        }

        echo "\n\n";
    }

    exit(1);
}

function prepareSupportedArgumentsArray(&$arr)
{
    $tmpArgs = Array();
    foreach( $arr as &$arg )
    {
        $tmpArgs[strtolower($arg['niceName'])] = $arg;
    }
    $arr= $tmpArgs;
}

