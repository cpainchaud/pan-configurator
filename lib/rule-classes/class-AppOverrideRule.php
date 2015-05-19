<?php
/*
 * Copyright (c) 2014 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
 * Author: Christophe Painchaud <cpainchaud _AT_ paloaltonetworks.com>
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

    static protected $templatexml = '<entry name="**temporarynamechangeme**"><from><member>any</member></from><to><member>any</member></to>
<source><member>any</member></source><destination><member>any</member></destination><port></port><protocol>tcp</protocol><application></application></entry>';


    /** @var AppRuleContainer */
    public $apps = null;

    protected $negatedSource = false;
    protected $negatedDestination = false;

    public $_protocol = '';
    public $_ports = '';

    /** @var  App|null */
    protected $_app;

    public function AppOverrideRule($owner, $fromTemplateXML=false)
    {
        $this->owner = $owner;

        $this->findParentAddressStore();

        $this->init_tags_with_store();
        $this->init_from_with_store();
        $this->init_to_with_store();
        $this->init_source_with_store();
        $this->init_destination_with_store();


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


        //  											//
        //	Begin of <disabled> extraction				//
        //												//
        $this->extract_disabled_from_domxml();
        // End of <disabled> properties extraction		//

        //  											//
        //	Begin of <description> extraction			//
        //												//
        $this->extract_description_from_domxml();
        // End of <description> extraction 				//


        $this->load_source();
        $this->load_destination();
        $this->load_tags();
        $this->load_from();
        $this->load_to();


        //
        // Begin <negate-source> extraction
        //
        $negatedSourceRoot = DH::findFirstElement('negate-source', $xml);
        if( $negatedSourceRoot !== false )
            $this->negatedSource = yesNoBool($negatedSourceRoot->textContent);
        else
            $this->negatedSource = false;
        // End of <negate-source>
        //

        // Begin <negate-destination> extraction
        //
        $negatedDestinationRoot = DH::findFirstElement('negate-destination', $xml);
        if( $negatedDestinationRoot !== false )
            $this->negatedDestination = yesNoBool($negatedDestinationRoot->textContent);
        else
            $this->negatedDestination = false;
        // End of <negate-destination>

        // <protocol> extraction
        //
        $protocolRoot = DH::findFirstElementOrCreate('protocol', $xml, 'tcp');
        $this->_protocol = $protocolRoot->textContent;
        //

        // <port> extraction
        //
        $portRoot = DH::findFirstElementOrCreate('port', $xml);
        $this->_port = $protocolRoot->textContent;
        //


    }


    public function sourceIsNegated()
    {
        return $this->negatedSource;
    }

    /**
     * @param bool $yes
     * @return bool
     */
    public function setSourceIsNegated($yes)
    {
        if( $this->negatedSource != $yes )
        {
            $tmpRoot = DH::findFirstElement('negate-source', $this->xmlroot);
            if( $tmpRoot === false )
            {
                if($yes)
                    DH::createElement($this->xmlroot, 'negate-source', 'yes');
            }
            else
            {
                if( !$yes )
                    $this->xmlroot->removeChild($tmpRoot);
                else
                    DH::setDomNodeText($tmpRoot, 'yes');
            }

            $this->negatedSource = $yes;

            return true;
        }

        return false;
    }


    /**
     * @param bool $yes
     * @return bool
     */
    public function API_setSourceIsNegated($yes)
    {
        $ret = $this->setSourceIsNegated($yes);

        if( $ret )
        {
            $con = findConnectorOrDie($this);
            $con->sendSetRequest($this->getXPath(), '<negate-source>'.boolYesNo($yes).'</negate-source>');
        }

        return $ret;
    }


    public function destinationIsNegated()
    {
        return $this->negatedDestination;
    }

    /**
     * @param bool $yes
     * @return bool
     */
    public function setDestinationIsNegated($yes)
    {
        if( $this->negatedDestination != $yes )
        {
            $tmpRoot = DH::findFirstElement('negate-destination', $this->xmlroot);
            if( $tmpRoot === false )
            {
                if($yes)
                    DH::createElement($this->xmlroot, 'negate-destination', 'yes');
            }
            else
            {
                if( !$yes )
                    $this->xmlroot->removeChild($tmpRoot);
                else
                    DH::setDomNodeText($tmpRoot, 'yes');
            }

            $this->negatedDestination = $yes;

            return true;
        }

        return false;
    }

    /**
     * @param bool $yes
     * @return bool
     */
    public function API_setDestinationIsNegated($yes)
    {
        $ret = $this->setDestinationIsNegated($yes);

        if( $ret )
        {
            $con = findConnectorOrDie($this);
            $con->sendSetRequest($this->getXPath(), '<negate-destination>'.boolYesNo($yes).'</negate-destination>');
        }

        return $ret;
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
        print $padding."    Tags:  ".$this->tags->toString_inline()."\n";
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


}