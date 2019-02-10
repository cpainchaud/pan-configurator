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

class TemplateStack
{
    use ReferencableObject;
    use PathableName;
    use PanSubHelperTrait;

    /** @var PanoramaConf */
    public $owner;

    /** @var  array */
    public $templates = array();

    protected $FirewallsSerials = Array();

    /**
     * Template constructor.
     * @param string $name
     * @param PanoramaConf $owner
     */
    public function __construct($name, $owner)
    {
        $this->name = $name;
        $this->owner = $owner;
        $this->deviceConfiguration = new PANConf(null, null, $this);
    }

    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("templatestack name not found\n", $xml);

        #print "template-stack: ".$this->name."\n";
        $tmp = DH::findFirstElement('templates', $xml);

        if( $tmp !== FALSE )
        {
            foreach( $tmp->childNodes as $node )
            {
                if( $node->nodeType != XML_ELEMENT_NODE ) continue;

                $ldv = $node->textContent;
                $this->templates[] = $ldv;
                //print "Template '{$ldv}' found\n";
                //Todo: add reference to Template
            }
            #print_r( $this->templates );
        }

        $this->FirewallsSerials = $this->owner->managedFirewallsStore->get_serial_from_xml( $xml );
        foreach( $this->FirewallsSerials as $serial)
        {
            $managedFirewall = $this->owner->managedFirewallsStore->find( $serial );
            if( $managedFirewall !== null )
                $managedFirewall->addTemplateStack( $this->name );
        }
    }

    public function name()
    {
        return $this->name;
    }

    public function isTemplateStack()
    {
        return true;
    }

}

