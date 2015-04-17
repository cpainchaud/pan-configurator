<?php

/*
 * Copyright (c) 2014 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
 * Author: Christophe Painchaud cpainchaud _AT_ paloaltonetworks.com
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

class DecryptionRule extends Rule
{

    public function DecryptionRule($owner, $fromTemplateXML=false)
    {
        $this->owner = $owner;

        $this->findParentAddressStore();
        $this->findParentServiceStore();

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
        if( $this->name === FALSE )
            derr("name not found\n");

        $this->extract_disabled_from_domxml();
        $this->extract_description_from_domxml();


        $this->load_from();
        $this->load_to();
        $this->load_source();
        $this->load_destination();
        $this->load_tags();

    }

    public function display()
    {
        $dis = '';
        if( $this->disabled )
            $dis = '<disabled>';

        print "*Rule named '".$this->name."  $dis\n";
        print "  From: " .$this->from->toString_inline()."  |  To:  ".$this->to->toString_inline()."\n";
        print "  Source: ".$this->source->toString_inline()."\n";
        print "  Destination: ".$this->destination->toString_inline()."\n";
        print "    Tags:  ".$this->tags->toString_inline()."\n";
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

} 