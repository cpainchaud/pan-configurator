<?php



/** @ignore */
class CallContext
{
    public $arguments = Array();

    /** @var  $object Rule|SecurityRule|NatRule|DecryptionRule */
    public $object;

    public $actionRef;

    public $isAPI = false;

    /** @var  $baseObject PANConf|PanoramaConf */
    public $baseObject;

    public $connector = null;

    public $padding = '';

    public function CallContext($actionProperties, $arguments)
    {
        $this->actionRef = $actionProperties;
        $this->prepareArgumentsForAction($arguments);
    }

    public function executeAction($object)
    {
        $this->object = $object;

        print "   - object '" . PH::boldText($object->name()) . "' passing through Action='{$this->actionRef['name']}'";

        if( count($this->arguments) != 0 )
        {
            print " Args: ";
            foreach($this->arguments as $argName => $argValue)
            {
                print "$argName=$argValue, ";
            }
        }

        print "\n";

        $this->actionRef['MainFunction']($this);
    }

    public function prepareArgumentsForAction($arguments)
    {
        $this->arguments = Array();

        if(strlen($arguments) != 0 && !isset($this->actionRef['args']) )
            display_error_usage_exit("error while processing argument '{$this->actionRef['name']}' : arguments were provided while they are not supported by this action");

        if(!isset($this->actionRef['args']) || $this->actionRef['args'] === false )
            return;

        $ex = explode(',', $arguments);

        if( count($ex) > count($this->actionRef['args']) )
            display_error_usage_exit("error while processing argument '{$this->actionRef['name']}' : too many arguments provided");

        $count = -1;
        foreach( $this->actionRef['args'] as $argName => &$properties )
        {
            $count++;

            $argValue = null;
            if( isset($ex[$count]) )
                $argValue = $ex[$count];


            if( (!isset($properties['default']) || $properties['default'] == '*nodefault*') && ($argValue === null || strlen($argValue)) == 0 )
                derr("action '{$this->actionRef['name']}' argument#{$count} '{$argName}' requires a value, it has no default one");

            if( $argValue !== null && strlen($argValue) > 0)
                $argValue = trim($argValue);
            else
                $argValue = $properties['default'];

            if( $properties['type'] == 'string' )
            {
                if( isset( $properties['choices']) )
                {
                    $argValue = strtolower($argValue);
                    if( !isset($properties['choices'][$argValue]) )
                        derr("unsupported value '{$argValue}' for action '{$this->actionRef['name']}' arg#{$count} '{$argName}'");
                }
            }
            elseif( $properties['type'] == 'boolean' )
            {
                if( $argValue == '1' || strtolower($argValue) == 'true' || strtolower($argValue) == 'yes' )
                    $argValue = true;
                elseif( $argValue == '0' || strtolower($argValue) == 'false' || strtolower($argValue) == 'no' )
                    $argValue = false;
                else
                    derr("unsupported argument value '{$argValue}' which should of type '{$properties['type']}' for  action '{$this->actionRef['name']}' arg#{$count} helper#'{$argName}'");
            }
            elseif( $properties['type'] == 'integer' )
            {
                if( !is_integer($argValue) )
                    derr("unsupported argument value '{$argValue}' which should of type '{$properties['type']}' for  action '{$this->actionRef['name']}' arg#{$count} helper#'{$argName}'");
            }
            else
            {
                derr("unsupported argument type '{$properties['type']}' for  action '{$this->actionRef['name']}' arg#{$count} helper#'{$argName}'");
            }
            $this->arguments[$argName] = $argValue;
        }

    }

    public function toString()
    {
        $ret = '';

        $ret .= "Action:'{$this->actionRef['name']}'";

        if( count($this->arguments) != 0 )
        {
            $ret .= " / Args: ";
            foreach($this->arguments as $argName => $argValue)
            {
                $ret .= "$argName=$argValue, ";
            }
        }

        return $ret;
    }
}
