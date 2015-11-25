<?php


class PbfRule extends RuleWithUserID
{
    /**
     * @param RuleStore $owner
     * @param bool $fromTemplateXML
     */
    public function __construct($owner,$fromTemplateXML=false)
    {
        $this->owner = $owner;

        $this->parentAddressStore = $this->owner->owner->addressStore;
        $this->parentServiceStore = $this->owner->owner->serviceStore;

        $this->tags = new TagRuleContainer($this);

        $this->from = new ZoneRuleContainer($this);
        $this->from->name = 'from';

        $this->to = new ZoneRuleContainer($this);
        $this->to->name = 'to';

        $this->source = new AddressRuleContainer($this);
        $this->source->name = 'source';
        $this->source->parentCentralStore = $this->parentAddressStore;

        $this->destination = new AddressRuleContainer($this);
        $this->destination->name = 'destination';
        $this->destination->parentCentralStore = $this->parentAddressStore;

        if( $fromTemplateXML )
        {
            $xmlElement = DH::importXmlStringOrDie($owner->xmlroot->ownerDocument, self::$templatexml);
            $this->load_from_domxml($xmlElement);
        }
    }


    /**
     * @param DOMElement $xml
     * @throws Exception
     */
    public function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if ($this->name === FALSE)
            derr("name not found\n");

        $this->extract_disabled_from_domxml();
        $this->extract_description_from_domxml();

        $this->load_source();
        $this->load_destination();
        $this->load_tags();
        $this->load_from();
        $this->load_to();

        $this->userID_loadUsersFromXml();
    }

    /**
     * Helper function to quickly print a function properties to CLI
     */
    public function display( $padding = 0)
    {
        $padding = str_pad('', $padding);

        $dis = '';
        if( $this->disabled )
            $dis = '<disabled>';

        print $padding."*Rule named '{$this->name}' $dis\n";
        print $padding."  Action: {$this->action()}    Type:{$this->type()}\n";
        print $padding."  From: " .$this->from->toString_inline()."  |  To:  ".$this->to->toString_inline()."\n";
        print $padding."  Source: ".$this->source->toString_inline()."\n";
        print $padding."  Destination: ".$this->destination->toString_inline()."\n";
        if( !$this->userID_IsCustom() )
            print $padding."  User: *".$this->userID_type()."*\n";
        else
        {
            $users = $this->userID_getUsers();
            print $padding . "  User:  " . PH::list_to_string($users) . "\n";
        }
        print $padding."    Tags:  ".$this->tags->toString_inline()."\n";
        print "\n";
    }

    public function ruleNature()
    {
        return 'pbf';
    }


    static protected $templatexml = '<entry name="**temporarynamechangeme**"><from><member>any</member></from><to><member>any</member></to>
<source><member>any</member></source><destination><member>any</member></destination></entry>';
}