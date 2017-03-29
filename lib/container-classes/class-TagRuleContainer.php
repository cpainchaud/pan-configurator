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
 * Class TagRuleContainer
 * @property Tag[] $o
 * @property Rule $owner
 */
class TagRuleContainer extends ObjRuleContainer
{
    /** @var null|TagStore */
    public $parentCentralStore = null;

    public function __construct($owner)
    {
        $this->owner = $owner;
        $this->name = 'tag';

        $this->findParentCentralStore();
    }


    public function removeAllTags()
    {
        $this->removeAll();
        $this->rewriteXML();
    }

    public function removeTag( Tag $tag, $rewriteXML = true)
    {

        $ret = $this->remove($tag);

        if( $ret && $rewriteXML )
        {
            $this->rewriteXML();
        }

        return $ret;
    }

    public function API_removeTag( Tag $tag, $rewriteXML = true)
    {
        if( $this->removeTag($tag, $rewriteXML) )
        {
            $con = findConnectorOrDie($this);
            $xpath = $this->getXPath()."/member[text()='".$tag->name()."']";
            $con->sendDeleteRequest($xpath);

            return true;
        }

        return false;
    }


    public function merge(TagRuleContainer $container, $exclusionFilter = null)
    {
        $change = false;
        foreach( $container->o as $obj )
        {
            if( !$this->has($obj) )
            {
                $exclude = false;
                if( $exclusionFilter !== null )
                {
                    foreach( $exclusionFilter as &$filter )
                    {
                        if( strpos($obj->name(), $filter) === 0 )
                        {
                            $exclude = true;
                            break;
                        }
                    }
                }

                if( !$exclude )
                {
                    $change = true;
                    $this->addTag($obj);
                }
            }
        }

        return $change;
    }

    /**
     * @param Tag|string can be Tag object or tag name (string). this is case sensitive
     * @param bool
     * @return bool
     */
    public function hasTag( $tag, $caseSensitive = true )
    {
        return $this->has($tag, $caseSensitive);
    }

    /**
     * @param Tag|string can be Tag object or tag name (string). this is case sensitive
     * @return bool
     */
    public function hasTagRegex( $regex )
    {
        return $this->hasObjectRegex($regex);
    }


    /**
     * add a Tag to this container
     * @param string|Tag
     * @param bool
     * @return bool
     */
    public function addTag( $Obj, $rewriteXML = true )
    {
        if( is_string($Obj) )
        {
            $f = $this->parentCentralStore->findOrCreate($Obj);
            if( $f === null )
            {
                derr(": Error : cannot find tag named '".$Obj."'\n");
            }
            return $this->addTag($f);
        }

        $ret = $this->add($Obj);

        if( $ret && $rewriteXML )
        {
            $this->rewriteXML();
        }

        return $ret;
    }

    /**
     * @param Tag|String $Obj
     * @param bool|true $rewriteXML
     * @return bool
     */
    public function API_addTag($Obj, $rewriteXML = true)
    {
        if( $this->addTag($Obj, $rewriteXML) )
        {
            $con = findConnectorOrDie($this);

            $con->sendSetRequest($this->getXPath(), '<member>'.$Obj->name().'</member>');

            return true;
        }

        return false;
    }

    public function &getXPath()
    {
        $xpath = $this->owner->getXPath().'/tag';
        return $xpath;
    }


    /**
     * returns a copy of current Tag array
     * @return Tag[]
     */
    public function tags()
    {
        return $this->o;
    }


    /**
     * @param DOMElement $xml
     *      * should only be called from a Rule constructor
     * @ignore
     */
    public function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;
        $toBeCleaned = Array();

        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != 1 ) continue;

            if( strlen($node->textContent) < 1 )
            {
                mwarning('invalid (empty) tag name found in rule "'.$this->owner->toString().'", IT WILL BE CLEANED', $node);
                $toBeCleaned[] = $node;
            }
            else
            {
                $f = $this->parentCentralStore->findOrCreate($node->textContent, $this);
                $this->o[] = $f;
            }
        }

        foreach($toBeCleaned as $cleanMe)
        {
            $xml->removeChild($cleanMe);
        }
    }

    public function rewriteXML()
    {
        if( count($this->o) > 0 )
        {
            if( $this->xmlroot === null )
                $this->xmlroot = DH::createElement($this->owner->xmlroot, 'tag');
            DH::Hosts_to_xmlDom($this->xmlroot, $this->o, 'member', false);
        }
        else
        {
            if( $this->xmlroot !== null )
            {
                $this->owner->xmlroot->removeChild($this->xmlroot);
                $this->xmlroot = null;
            }
        }
    }


    /**
     *
     * @ignore
     */
    protected function findParentCentralStore()
    {
        $this->parentCentralStore = null;

        $cur = $this;
        while( isset($cur->owner) && $cur->owner !== null )
        {
            $ref = $cur->owner;
            if( isset($ref->tagStore) &&
                $ref->tagStore !== null		)
            {
                $this->parentCentralStore = $ref->tagStore;
                return;
            }
            $cur = $ref;
        }

    }

    public function copy(TagRuleContainer $other)
    {
        $this->removeAll();

        foreach( $other->o as $member )
        {
            $this->add($member);
        }

        $this->rewriteXML();
    }

}



