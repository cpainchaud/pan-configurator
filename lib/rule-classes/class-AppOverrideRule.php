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


class AppOverrideRule extends Rule
{
    use NegatableRule;

    static public $templatexml = '<entry name="**temporarynamechangeme**"><from><member>any</member></from><to><member>any</member></to>
<source><member>any</member></source><destination><member>any</member></destination><port></port><protocol>tcp</protocol><application></application></entry>';


    public $_protocol = '';
    public $_ports = '';

    /** @var  App|null */
    protected $_app;

    /**
     * @param RuleStore $owner
     * @param bool $fromTemplateXML
     */
    public function __construct($owner, $fromTemplateXML=false)
    {
        $this->owner = $owner;

        $this->parentAddressStore = $this->owner->owner->addressStore;
        $this->parentServiceStore = $this->owner->owner->serviceStore;

        $this->tags = new TagRuleContainer($this);

        $this->from = new ZoneRuleContainer($this);
        $this->from->name = 'from';
        $this->from->parentCentralStore = $owner->owner->zoneStore;

        $this->to = new ZoneRuleContainer($this);
        $this->to->name = 'to';
        $this->to->parentCentralStore = $owner->owner->zoneStore;

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


    public function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if ($this->name === FALSE)
            derr("name not found\n");


        $this->load_common_from_domxml();

        $this->load_source();
        $this->load_destination();
        $this->load_from();
        $this->load_to();

        $this->_readNegationFromXml();

        // <application> extraction
        //
        $applicationRoot = DH::findFirstElementOrCreate('application', $xml);
        $this->_app = $this->owner->owner->appStore->findOrCreate($applicationRoot->textContent, $this);
        //

        // <protocol> extraction
        //
        $protocolRoot = DH::findFirstElementOrCreate('protocol', $xml, 'tcp');
        $this->_protocol = $protocolRoot->textContent;
        //

        // <port> extraction
        //
        $portRoot = DH::findFirstElementOrCreate('port', $xml);
        $this->_ports = $portRoot->textContent;
        //


    }

    public function display( $padding = 0)
    {
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
        print $padding."  Application:  ".$this->_app->name()."\n";
        print $padding."  Protocol:  ".$this->_protocol."    Port:  ".$this->_ports."\n";
        print $padding."    Tags:  ".$this->tags->toString_inline()."\n";

        if( strlen($this->_description) > 0 )
            print $padding."  Desc:  ".$this->_description."\n";

        print "\n";
    }


    public function protocol()
    {
        return $this->_protocol;
    }

    public function isTcp()
    {
        return $this->_protocol == 'tcp';
    }

    public function isUdp()
    {
        return $this->_protocol == 'udp';
    }

    public function setTcp()
    {
        $protocolRoot = DH::findFirstElementOrCreate('protocol', $this->xmlroot);
        $this->_protocol = 'tcp';

        DH::setDomNodeText($protocolRoot, $this->_protocol);
    }

    public function setUdp()
    {
        $protocolRoot = DH::findFirstElementOrCreate('protocol', $this->xmlroot);
        $this->_protocol = 'udp';

        DH::setDomNodeText($protocolRoot, $this->_protocol);
    }

    public function ports()
    {
        return $this->_ports;
    }

    /**
     * @param $ports string
     */
    public function setPorts($ports)
    {
        $portRoot = DH::findFirstElementOrCreate('port', $this->xmlroot);
        $this->_ports = $ports;

        DH::setDomNodeText($portRoot, $this->_ports);
    }

    public function application()
    {
        return $this->application();
    }

    /** @param App|null $app
     * @return bool */
    public function setApplication($app)
    {
        if( $app === null )
            derr("app cannot be null");

        if( $this->_app !== $app )
        {
            if ($this->_app !== null)
                $this->_app->removeReference($this);

            $app->addReference($this);
            $this->_app = $app;

            $root = DH::findFirstElementOrCreate('application', $this->xmlroot);

            DH::setDomNodeText($root, $app->name());

            return true;
        }
        return false;
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

        if( $this->_app !== null )
        {
            $this->_app->removeReference($this);
            unset($this->_app);
        }

        $this->owner = null;
    }

    public function isAppOverrideRule()
    {
        return true;
    }

    public function ruleNature()
    {
        return 'app-override';
    }

    public function storeVariableName()
    {
        return "appOverrideRules";
    }

}