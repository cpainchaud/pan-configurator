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

class VirtualWire
{
    use XmlConvertible;
    use PathableName;
    use ReferencableObject;

    /** @var VirtualWireStore */
    public $owner;

    /** @var InterfaceContainer */
    public $attachedInterface1;

    /** @var InterfaceContainer */
    public $attachedInterface2;
    /**
     * @param $name string
     * @param $owner VirtualWireStore
     */
    public function __construct($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;
    }

    /**
     * @param DOMElement $xml
     */
    public function load_from_domxml( $xml )
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("virtual-wire name not found\n");

        $this->attachedInterface1 = DH::findFirstElementOrCreate('interface1', $xml)->textContent;
        $this->attachedInterface2 = DH::findFirstElementOrCreate('interface2', $xml)->textContent;
    }


    /**
     * @return VirtualSystem[]
     */
    public function &findConcernedVsys()
    {
        $vsysList = Array();
        foreach($this->attachedInterfaces->interfaces() as $if )
        {
            $vsys = $this->owner->owner->network->findVsysInterfaceOwner($if->name());
            if( $vsys !== null )
                $vsysList[$vsys->name()] = $vsys;
        }

        return $vsysList;
    }
}
