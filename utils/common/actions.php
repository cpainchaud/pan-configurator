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

    /** @var  $subSystem VirtualSystem|PANConf|PanoramaConf|DeviceGroup */
    public $subSystem;

    /** @var PanAPIConnector */
    public $connector = null;

    public $padding = '';

    public $nestedQueries;

    public function __construct($actionProperties, $arguments, $nestedQueries = null)
    {
        $this->actionRef = $actionProperties;
        $this->prepareArgumentsForAction($arguments);

        if( $nestedQueries === null )
            $nestedQueries = Array();
        else
            $this->nestedQueries = &$nestedQueries;
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
                if( is_bool($argValue) )
                    print "$argName=".boolYesNo($argValue).", ";
                else
                    print "$argName=$argValue, ";
            }
        }

        print "\n";

        $this->actionRef['MainFunction']($this);
    }

    public function hasGlobalFinishAction()
    {
        return isset($this->actionRef['GlobalFinishFunction']);
    }

    public function executeGlobalFinishAction()
    {
        print "   - action '{$this->actionRef['name']}' has tasks to process before shutdown.\n";
        $this->actionRef['GlobalFinishFunction']($this);
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
                    foreach($properties['choices'] as $choice )
                    {
                        $tmpChoice[strtolower($choice)] = true;
                    }
                    $argValue = strtolower($argValue);
                    if( !isset($tmpChoice[$argValue]) )
                        derr("unsupported value '{$argValue}' for action '{$this->actionRef['name']}' arg#{$count} '{$argName}'");
                }
            }
            elseif( $properties['type'] == 'boolean' || $properties['type'] == 'bool' )
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
                if( is_bool($argValue) )
                    $ret .= "$argName=".boolYesNo($argValue).", ";
                else
                    $ret .= "$argName=$argValue, ";
            }
        }

        return $ret;
    }
}

class RuleCallContext extends CallContext
{
    public function addRuleToMergedApiChange($setValue)
    {
        $rule = $this->object;

        if( !isset($this->mergeArray) )
            $this->mergeArray = Array();

        $mergeArray = &$this->mergeArray;
        $panoramaMode = $this->baseObject->isPanorama();
        $subSystem = $this->subSystem;


        $classToType = Array('SecurityRule' => 'security', 'NatRule' => 'nat', );
        $type = $classToType[get_class($rule)];

        if( !$panoramaMode )
        {
            $mergeArray[$subSystem->name()][$type][$rule->name()] = $setValue;
            return;
        }

        $ruleLocation = 'pre-rulebase';
        if( $rule->isPostRule() )
            $ruleLocation = 'post-rulebase';

        if( $rule->owner->owner->isPanorama() )
            $mergeArray['shared'][$ruleLocation][$type][$rule->name()] = $setValue;
        else
            $mergeArray[$subSystem->name()][$ruleLocation][$type][$rule->name()] = $setValue;
    }


    public function generateRuleMergedApuChangeString($forSharedRules=false)
    {

        if( !isset($this->mergeArray) )
            return '';

        $mergeArray = &$this->mergeArray;

        if( count($mergeArray) < 1 )
            return '';

        if( $this->baseObject->isPanorama() )
        {
            $strPointer = '';

            if( $forSharedRules && !isset($mergeArray['shared']) )
                return null;

            foreach($mergeArray as $subSystemName => &$locations)
            {
                if( $subSystemName == 'shared' )
                {
                    if( !$forSharedRules )
                        continue;
                }
                else
                {
                    if( $forSharedRules )
                        continue;
                }

                if( !$forSharedRules )
                    $strPointer .= "<entry name=\"{$subSystemName}\">";

                foreach($locations as $locationName => &$types)
                {
                    $strPointer .= "<{$locationName}>";

                    foreach($types as $typeName => &$rules)
                    {
                        $strPointer .= "<{$typeName}><rules>\n";

                        foreach($rules as $ruleName => $xmlValue )
                        {
                            $strPointer .= "<entry name=\"{$ruleName}\">{$xmlValue}</entry>\n";
                        }

                        $strPointer .= "</rules></{$typeName}>\n";
                    }

                    $strPointer .= "</{$locationName}>";
                }

                if( !$forSharedRules )
                    $strPointer .= "</entry>";
            }

            if( $forSharedRules )
                return $strPointer;

            if( strlen($strPointer) < 1 )
                return null;

            return '<device-group>'.$strPointer.'</device-group>';
        }
        else
        {
            if( count($mergeArray) < 1 )
                return null;

            $xml = '<vsys>';
            foreach($mergeArray as $subSystemName => &$types)
            {
                $xml .= "<entry name=\"{$subSystemName}\"><rules>";

                foreach($types as $typeName => &$rules)
                {
                    $xml .= "<{$typeName}><rules>\n";

                    foreach($rules as $ruleName => $xmlValue )
                    {
                        $xml .= "<entry name=\"{$ruleName}\">{$xmlValue}</entry>\n";
                    }

                    $xml .= "</rules></{$typeName}>\n";
                }

                $xml .= "</rules></entry>";
            }
            $xml .= '</vsys>';

            return $xml;
        }
    }
}
