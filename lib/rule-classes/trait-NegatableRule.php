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

/**
 *
 * @property DOMElement $xmlroot
 */
trait NegatableRule
{
    protected $_sourceIsNegated = false;
    protected $_destinationIsNegated = false;

    public function sourceIsNegated()
    {
        return $this->_sourceIsNegated;
    }

    public function destinationIsNegated()
    {
        return $this->_destinationIsNegated;
    }

    protected function _readNegationFromXml()
    {
        $xml = $this->xmlroot;

        $sourceFound = false;
        $destinationFound = false;

        foreach($xml->childNodes as $node )
        {
            if( $sourceFound && $destinationFound )
                return;

            /** @var DOMElement $node */
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            if( $node->tagName == 'negate-source' )
                $this->_sourceIsNegated = yesNoBool($node->textContent);
            else if( $node->tagName == 'negate-destination' )
                $this->_destinationIsNegated = yesNoBool($node->textContent);
        }
    }

    /**
     * @param bool $yes
     * @return bool
     */
    public function setSourceIsNegated($yes)
    {
        if( $this->_sourceIsNegated != $yes )
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

            $this->_sourceIsNegated = $yes;

            return true;
        }

        return false;
    }

    /**
     * @param bool $yes
     * @return bool
     */
    public function setDestinationIsNegated($yes)
    {
        if( $this->_destinationIsNegated != $yes )
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

            $this->_destinationIsNegated = $yes;

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


}