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

/**
 * @property $xmlroot DOMElement|null
 */
trait ObjectWithDescription
{
    /** @var null|string  */
    protected $_description = null;

    function description()
    {
        if( $this->_description === null )
            return '';

        return $this->_description;
    }

    /**
     * @param null|string $newDescription
     * @return bool
     */
    function setDescription($newDescription=null)
    {
        if( $newDescription === null || strlen($newDescription) < 1)
        {
            if($this->_description === null )
                return false;

            $this->_description = null;
            $tmpRoot = DH::findFirstElement('description', $this->xmlroot);

            if( $tmpRoot === false )
                return true;

            $this->xmlroot->removeChild($tmpRoot);
        }
        else
        {
            if( $this->_description == $newDescription )
                return false;
            $this->_description = $newDescription;
            $tmpRoot = DH::findFirstElementOrCreate('description', $this->xmlroot);
            DH::setDomNodeText( $tmpRoot, $this->description() );
        }

        return true;
    }

    protected function _load_description_from_domxml()
    {
        $descroot = DH::findFirstElement('description', $this->xmlroot );
        if( $descroot !== false )
            $this->_description = $descroot->textContent;
    }

}

