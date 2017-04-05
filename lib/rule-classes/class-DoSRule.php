<?php
/*
 * Copyright (c) 2014-2017 Christophe Painchaud <shellescape _AT_ gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.

 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/


class DoSRule extends RuleWithUserID
{
    use NegatableRule;

    static public $templatexml = '<entry name="**temporarynamechangeme**"><from><zone></zone></from><to><zone></zone>></to>
<protection/><source><member>any</member></source><destination><member>any</member></destination>
<source-user><member>any</member></source-user><service><member>any</member></service><action><deny/></action></entry>';
    static protected $templatexmlroot = null;

    const ActionDeny        = 'Deny';
    const ActionAllow       = 'Allow';
    const ActionProtect      = 'Protect';


    static private $RuleActions = Array(
        self::ActionDeny => 'deny',
        self::ActionAllow => 'allow',
        self::ActionProtect => 'protect'
    );

    protected $action = self::ActionDeny;

    /** @var ZoneRuleContainer|InterfaceContainer */
    public $from;

    /** @var ZoneRuleContainer|InterfaceContainer */
    public $to;

    protected $_zoneBasedFrom = true;
    protected $_zoneBasedTo = true;

    /**
     * For developer use only
     */
    protected function load_from()
    {
        $tmp = DH::findFirstElementOrCreate('from', $this->xmlroot);

        $tmp = DH::firstChildElement($tmp);
        if( $tmp === null )
            derr("DOS rule has nothing inside <from> tag, please fix before going forward");

        if( $tmp->tagName == 'zone' )
        {
            $this->_zoneBasedFrom = true;
            $this->from = new ZoneRuleContainer($this);
            $this->from->name = 'from';
            $this->from->findParentCentralStore();
            $this->from->load_from_domxml($tmp);
        }
        elseif( $tmp->tagName == 'interface' )
        {
            $this->_zoneBasedFrom = false;
            $this->from = new InterfaceContainer($this, $this->owner->_networkStore);
            $this->from->name = 'from';
            $this->from->load_from_domxml($tmp);
        }
        else
            derr("DOS rule has unsupported <from> type '{$tmp->tagName}'");
    }


    /**
     * For developer use only
     */
    protected function load_to()
    {
        $tmp = DH::findFirstElementOrCreate('to', $this->xmlroot);

        $tmp = DH::firstChildElement($tmp);
        if( $tmp === null )
            derr("DOS rule has nothing inside <to> tag, please fix before going forward");

        if( $tmp->tagName == 'zone' )
        {
            $this->_zoneBasedTo = true;
            $this->to = new ZoneRuleContainer($this);
            $this->to->name = 'to';
            $this->to->findParentCentralStore();
            $this->to->load_from_domxml($tmp);
        }
        elseif( $tmp->tagName == 'interface' )
        {
            $this->_zoneBasedTo = false;
            $this->to = new InterfaceContainer($this,$this->owner->_networkStore);
            $this->to->name = 'to';
            $this->to->load_from_domxml($tmp);
        }
        else
            derr("DOS rule has unsupported <to> type '{$tmp->tagName}'");
    }

    /**
     * DoSRule constructor.
     * @param RuleStore $owner
     * @param bool $fromTemplateXML
     */
    public function __construct($owner, $fromTemplateXML=false)
    {
        $this->owner = $owner;

        $this->parentAddressStore = $this->owner->owner->addressStore;
        $this->parentServiceStore = $this->owner->owner->serviceStore;

        $this->tags = new TagRuleContainer($this);

        $this->source = new AddressRuleContainer($this);
        $this->source->name = 'source';
        $this->source->parentCentralStore = $this->parentAddressStore;

        $this->destination = new AddressRuleContainer($this);
        $this->destination->name = 'destination';
        $this->destination->parentCentralStore = $this->parentAddressStore;

        $this->services = new ServiceRuleContainer($this);
        $this->services->name = 'service';

        if( $fromTemplateXML )
        {
            $xmlElement = DH::importXmlStringOrDie($owner->xmlroot->ownerDocument, self::$templatexml);
            $this->load_from_domxml($xmlElement);
        }
    }


    public function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("name not found\n");

        $this->load_common_from_domxml();


        $this->load_source();
        $this->load_destination();
        $this->load_from();
        $this->load_to();

        //										//
        // Begin <service> extraction			//
        //										//
        $tmp = DH::findFirstElementOrCreate('service', $xml);
        $this->services->load_from_domxml($tmp);
        // end of <service> zone extraction

        $this->_readNegationFromXml();

        //
        // Begin <action> extraction
        //
        $tmp = DH::findFirstElement('action', $xml);
        $tmp = DH::firstChildElement($tmp);
        if( $tmp !== false )
        {
            $actionFound = array_search($tmp->nodeName, self::$RuleActions);
            if( $actionFound === false )
            {
                mwarning("unsupported action '{$tmp->nodeName}' found, Deny assumed" , $tmp);
            }
            else
            {
                $this->action = $actionFound;
            }
        }
        else
        {
            mwarning("'<action> not found, assuming 'Deny'" ,$xml);
        }
        // End of <rule-type>

        $this->userID_loadUsersFromXml();
    }

    public function action()
    {
        return self::$RuleActions[$this->action];
    }


    public function display( $padding = 0)
    {
        if( !is_string($padding) )
            $padding = str_pad('', $padding);

        $dis = '';
        if( $this->disabled )
            $dis = '<disabled>';

        $sourceNegated = '';
        if( $this->sourceIsNegated() )
            $sourceNegated = '*negated*';

        $destinationNegated = '';
        if( $this->destinationIsNegated() )
            $destinationNegated = '*negated*';


        print $padding."*Rule named '{$this->name}' $dis\n";
        print $padding."  From: " .$this->from->toString_inline()."  |  To:  ".$this->to->toString_inline()."\n";

        print $padding."  Source: $sourceNegated ".$this->source->toString_inline()."\n";
        print $padding."  Destination: $destinationNegated ".$this->destination->toString_inline()."\n";

        print $padding."  Service:  ".$this->services->toString_inline()."\n";
        if( !$this->userID_IsCustom() )
            print $padding."  User: *".$this->userID_type()."*\n";
        else
        {
            $users = $this->userID_getUsers();
            print $padding . " User:  " . PH::list_to_string($users) . "\n";
        }
        print $padding."  Action: {$this->action()}\n";
        print $padding."    Tags:  ".$this->tags->toString_inline()."\n";

        if( strlen($this->_description) > 0 )
            print $padding."  Desc:  ".$this->_description."\n";

        print "\n";
    }

    public function cleanForDestruction()
    {
        $this->from->__destruct();
        $this->to->__destruct();
        $this->source->__destruct();
        $this->destination->__destruct();
        $this->tags->__destruct();


        $this->from = null;
        $this->to = null;
        $this->source = null;
        $this->destination = null;
        $this->tags = null;

        $this->owner = null;
    }

    public function isDoSRule()
    {
        return true;
    }

    public function ruleNature()
    {
        return 'dos';
    }

    public function isZoneBasedFrom()
    {
        return $this->_zoneBasedFrom;
    }

    public function isZoneBasedTo()
    {
        return $this->_zoneBasedTo;
    }

    public function isInterfaceBasedFrom()
    {
        return !$this->_zoneBasedFrom;
    }

    public function isInterfaceBasedTo()
    {
        return !$this->_zoneBasedTo;
    }

    public function storeVariableName()
    {
        return "dosRules";
    }

}