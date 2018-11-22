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
 * @property DOMElement|null $xmlroot
 */
trait ObjectWithDescription
{
    /** @var string  */
    protected $_description = null;

    /**
     * @return string if no description then string will be empty: ''
     */
    function description()
    {
        if( $this->_description === null )
            return '';

        return $this->_description;
    }

    /**
     * @param null|string $newDescription  empty or null description will erase existing one
     * @return bool false if no update was made to description (already had same value)
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
            DH::setDomNodeText( $tmpRoot, $this->_description );
        }

        return true;
    }


    /**
     * @param string $newDescription
     * @return bool true if value was changed
     */
    public function API_setDescription($newDescription)
    {
        $ret = $this->setDescription($newDescription);
        if( $ret )
        {
            $xpath = $this->getXPath().'/description';
            $con = findConnectorOrDie($this);

            if( strlen($this->_description) < 1 )
                $con->sendDeleteRequest($xpath);
            else
                $con->sendSetRequest($this->getXPath(), '<description>'.htmlspecialchars($this->_description).'</description>');

        }

        return $ret;
    }

    public function description_merge( Rule $other )
    {
        $description = $this->description();
        $other_description = $other->description();

        $new_description = $description;

        //Todo: validation needed
        //1) to long
        //2) take half max of first and half max of second

        $description_len = strlen($description);
        $other_description_len = strlen($other_description);

        if( $this->owner->owner->version < 71 )
            $max_length = 253;
        else
            $max_length = 1020;

        if( $description_len + $other_description_len > $max_length )
        {
            if( $description_len > $max_length/2 && $other_description_len > $max_length/2  )
            {
                $new_description = substr( $description, 0, $max_length/2-1) ."|". substr($other_description, 0, $max_length/2-1);
            }
            else
                $new_description = substr( $description."|".$other_description, 0, $max_length );
        }
        else
            $new_description =  $description ."|". $other_description ;

        $this->setDescription( $new_description );
    }

    protected function _load_description_from_domxml()
    {
        $descroot = DH::findFirstElement('description', $this->xmlroot );
        if( $descroot !== false )
            $this->_description = $descroot->textContent;
    }

}

