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
/**
 * Class AddressRuleContainer
 * @property Address[]|AddressGroup[] $o
 * @property Rule|SecurityRule|NatRule $owner
 *
 */
class AddressRuleContainer extends ObjRuleContainer
{
    /**
     * @var null|string[]|DOMElement
     */
    public $xmlroot=null;

    /**
     * @var null|AddressStore
     */
    public $parentCentralStore = null;

    // TODO implement 'multicast' support

    public function AddressRuleContainer($owner)
    {
        $this->owner = $owner;
        $this->o = Array();

        $this->findParentCentralStore();
    }

    /**
     * @param Address|AddressGroup $Obj
     * @param bool $rewriteXml
     * @return bool
     */
    public function add( $Obj, $rewriteXml = true )
    {
        $this->fasthashcomp = null;

        $ret = parent::add($Obj);
        if( $ret && $rewriteXml )
        {
            $this->rewriteXML();
        }
        return $ret;
    }

    /**
     * @param Address|AddressGroup $Obj
     * @param bool $rewritexml
     * @return bool
     */
    public function API_add( $Obj, $rewritexml = true )
    {
        if( $this->add($Obj, $rewritexml) )
        {
            $xpath = &$this->getXPath();
            $con = findConnectorOrDie($this);

            if( count($this->o) == 1 )
            {
                $url = "type=config&action=delete&xpath=" . $xpath;
                $con->sendRequest($url);
            }

            $con->sendSetRequest($xpath, "<member>{$Obj->name()}</member>");

            return true;
        }

        return false;
    }


    /**
     * @param Address|AddressGroup $Obj
     * @param bool $rewriteXml
     * @param bool $forceAny
     *
     * @return bool  True if Zone was found and removed. False if not found.
     */
    public function remove( $Obj, $rewriteXml = true, $forceAny = false )
    {
        $count = count($this->o);

        $ret = parent::remove($Obj);

        if( $ret && $count == 1 && !$forceAny  )
        {
            derr("you are trying to remove last Object from a rule which will set it to ANY, please use forceAny=true for object: "
                .$this->toString() ) ;
        }

        if( $ret && $rewriteXml )
        {
            $this->rewriteXML();
        }
        return $ret;
    }

    /**
     * @param Address|AddressGroup $Obj
     * @param bool $rewriteXml
     * @param bool $forceAny
     * @return bool
     */
    public function API_remove( $Obj, $rewriteXml = true, $forceAny = false )
    {
        if( $this->remove($Obj, $rewriteXml, $forceAny) )
        {
            $xpath = &$this->getXPath();
            $con = findConnectorOrDie($this);

            if( count($this->o) == 0 )
            {
                $url = "type=config&action=delete&xpath=" . $xpath;
                $con->sendRequest($url);
                $url = "type=config&action=set&xpath=$xpath&element=<member>any</member>";
                $con->sendRequest($url);
                return true;
            }

            $url = "type=config&action=delete&xpath=" . $xpath."/member[text()='".$Obj->name()."']";
            $con->sendRequest($url);

            return true;
        }

        return false;
    }

    public function setAny()
    {
        foreach( $this->o as $o )
        {
            $this->remove($o, false, true);
        }

        $this->rewriteXML();
    }

    /**
     * @param Address|AddressGroup|string $object can be Address|AddressGroup object or object name (string)
     * @return bool
     */
    public function has( $object, $caseSensitive = true )
    {
        return parent::has($object, $caseSensitive);
    }



    /**
     * return an array with all objects
     * @return Address[]|AddressGroup[]
     */
    public function members()
    {
        return $this->o;
    }

    /**
     * return an array with all objects
     * @return Address[]|AddressGroup[]
     */
    public function all()
    {
        return $this->o;
    }
    

    /**
     * should only be called from a Rule constructor
     * @ignore
     */
    public function load_from_domxml($xml)
    {
        //print "started to extract '".$this->toString()."' from xml\n";
        $this->xmlroot = $xml;
        $i=0;
        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != 1 ) continue;

            if( $i == 0 && strtolower($node->textContent) == 'any' )
            {
                return;
            }

            $f = $this->parentCentralStore->findOrCreate( $node->textContent, $this);
            $this->o[] = $f;
            $i++;
        }
    }


    public function rewriteXML()
    {
        if( $this->xmlroot === null )
            return;

        if( $this->xmlroot !== null && $this->name == 'snathosts' && count($this->o) == 0 )
            DH::clearDomNodeChilds($this->xmlroot);
        else
            DH::Hosts_to_xmlDom($this->xmlroot, $this->o, 'member', true);
    }

    public function &toString_inline()
    {
        if( count($this->o) == 0 )
        {
            $out = '**ANY**';
            return $out;
        }

        $out = parent::toString_inline();
        return $out;
    }



    /**
     *
     * @ignore
     */
    protected function findParentCentralStore()
    {
        $this->parentCentralStore = null;

        if( $this->owner )
        {
            $currentObject = $this;
            while( isset($currentObject->owner) && !is_null($currentObject->owner) )
            {

                if( isset($currentObject->owner->addressStore) &&
                    !is_null($currentObject->owner->addressStore)				)
                {
                    $this->parentCentralStore = $currentObject->owner->addressStore;
                    //print $this->toString()." : found a parent central store: ".$parentCentralStore->toString()."\n";
                    return;
                }
                $currentObject = $currentObject->owner;
            }
        }

        mwarning('no parent store found!');

    }


    /**
     * Merge this set of objects with another one (in paramater). If one of them is 'any'
     * then the result will be 'any'.
     *
     */
    public function merge($other)
    {
        $this->fasthashcomp = null;

        // This is Any ? then merge = Any
        if( count($this->o) == 0 )
            return;

        // this other is Any ? then this one becomes Any
        if( count($other->o) == 0 )
        {
            $this->setAny();
            return;
        }

        foreach($other->o as $s)
        {
            $this->add($s);
        }

    }

    /**
     * To determine if a container has all the zones from another container. Very useful when looking to compare similar rules.
     * @param $other
     * @param $anyIsAcceptable
     * @return boolean true if Zones from $other are all in this store
     */
    public function includesContainer(AddressRuleContainer $other, $anyIsAcceptable=true )
    {

        if( !$anyIsAcceptable )
        {
            if( $this->count() == 0 || $other->count() == 0 )
                return false;
        }

        if( $this->count() == 0 )
            return true;

        if( $other->count() == 0 )
            return false;

        $objects = $other->members();

        foreach( $objects as $o )
        {
            if( !$this->has($o) )
                return false;
        }

        return true;

    }

    public function API_setAny()
    {
        $this->setAny();
        $xpath = &$this->getXPath();
        $con = findConnectorOrDie($this);

        $url = "type=config&action=delete&xpath=".$xpath;
        $con->sendRequest($url);

        $url = "type=config&action=set&xpath=$xpath&element=<member>any</member>";
        $con->sendRequest($url);
    }


    public function &getXPath()
    {

        $str = $this->owner->getXPath().'/'.$this->name;

        return $str;

    }

    /**
     * @return bool
     */
    public function isAny()
    {
        return ( count($this->o) == 0 );
    }


    /**
     * @param Address|AddressGroup
     * @param bool $anyIsAcceptable
     * @return bool
     */
    public function hasObjectRecursive( $object, $anyIsAcceptable=false)
    {
        if( $object === null )
            derr('cannot work with null objects');

        if( $anyIsAcceptable && $this->count() == 0 )
            return false;

        foreach( $this->o as $o )
        {
            if( $o === $object )
                return true;
            if( $o->isGroup() )
                if( $o->hasObjectRecursive($object) ) return true;
        }

        return false;
    }


    /**
     * To determine if a store has all the Address from another store, it will expand AddressGroups instead of looking for them directly. Very useful when looking to compare similar rules.
     * @param AddressRuleContainer $other
     * @param bool $anyIsAcceptable if any of these objects is Any the it will return false
     * @return bool true if Address objects from $other are all in this store
     */
    public function includesContainerExpanded(AddressRuleContainer $other, $anyIsAcceptable=true )
    {

        if( !$anyIsAcceptable )
        {
            if( $this->count() == 0 || $other->count() == 0 )
                return false;
        }

        if( $this->count() == 0 )
            return true;

        if( $other->count() == 0 )
            return false;

        $localA = Array();
        $A = Array();

        foreach( $this->o as $object )
        {
            if( $object->isGroup() )
            {
                $flat = $object->expand();
                $localA = array_merge($localA, $flat);
            }
            else
                $localA[] = $object;
        }
        $localA = array_unique_no_cast($localA);

        $otherAll = $other->all();

        foreach( $otherAll as $object )
        {
            if( $object->isGroup() )
            {
                $flat = $object->expand();
                $A = array_merge($A, $flat);
            }
            else
                $A[] = $object;
        }
        $A = array_unique_no_cast($A);

        $diff = array_diff_no_cast($A, $localA);

        if( count($diff) > 0 )
        {
            return false;
        }


        return true;

    }

}





