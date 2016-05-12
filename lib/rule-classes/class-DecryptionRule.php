<?php

/*
 * Copyright (c) 2014-2015 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
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

class DecryptionRule extends RuleWithUserID
{
    use NegatableRule;

    public function __construct($owner, $fromTemplateXML=false)
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

        $this->load_from();
        $this->load_to();
        $this->load_source();
        $this->load_destination();

        $this->userID_loadUsersFromXml();
        $this->_readNegationFromXml();

        //										//
        // Begin <service> extraction			//
        //										//
        if( $this->owner->owner->version >= 61 )
        {
            $tmp = DH::findFirstElementOrCreate('service', $xml);
            $this->services->load_from_domxml($tmp);
        }
        // end of <service> zone extraction

    }

    public function display($padding = 0)
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
        print $padding."  Service:  ".$this->services->toString_inline()."\n";
        if( !$this->userID_IsCustom() )
            print $padding."  User: *".$this->userID_type()."*\n";
        else
        {
            $users = $this->userID_getUsers();
            print $padding . " User:  " . PH::list_to_string($users) . "\n";
        }
        print $padding."  Tags:  ".$this->tags->toString_inline()."\n";

        if( $this->_targets !== null )
            print $padding."  Targets:  ".$this->targets_toString()."\n";

        if( strlen($this->_description) > 0 )
            print $padding."  Desc:  ".$this->_description."\n";
        print "\n";
    }


    public function isDecryptionRule()
    {
        return true;
    }

    public function storeVariableName()
    {
        return "decryptionRules";
    }

    public function ruleNature()
    {
        return 'decryption';
    }

} 