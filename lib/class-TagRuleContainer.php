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
 * Class TagRuleContainer
 * @property Tag[] $o
 * @property Rule $owner
 */
class TagRuleContainer extends ObjRuleContainer
{
    /**
     * @var null|string[]|DOMElement
     */
    public $xmlroot=null;

    /**
     * @var null|TagStore
     */
    public $parentCentralStore = null;

    public static $childn = 'Tag';

    public function TagRuleContainer($owner)
    {
        $this->classn = &self::$childn;

        $this->owner = $owner;
        $this->o = Array();

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
     *
     */
    public function findAvailableTagName($base, $suffix)
    {
        $maxl = 31;
        $basel = strlen($base);
        $suffixl = strlen($suffix);
        $inc = 1;
        $basePlusSuffixL = $basel + $suffixl;

        while(true)
        {

            $incl = strlen(strval($inc));

            if( $basePlusSuffixL + $incl > $maxl )
            {
                $newname = substr($base,0, $basel-$suffixl-$incl).$suffix.$inc;
            }
            else
                $newname = $base.$suffix.$inc;

            if( is_null($this->find($newname)) )
                return $newname;

            $inc++;
        }
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
     * should only be called from a Rule constructor
     * @ignore
     */
    public function load_from_xml(&$xml)
    {
        $this->xmlroot = &$xml;

        foreach( $xml['children'] as &$x )
        {
            //print "Trying to create tag '".$cur[$k[$i]]['content']."'\n";
            $f = $this->parentCentralStore->findOrCreate( $x['content'], $this);
            $this->o[] = $f;
        }

    }

    /**
     * should only be called from a Rule constructor
     * @ignore
     */
    public function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;

        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != 1 ) continue;
            $f = $this->parentCentralStore->findOrCreate( $node->textContent, $this);
            $this->o[] = $f;
        }
    }

    public function rewriteXML()
    {
        if( PH::$UseDomXML === TRUE )
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
                    $this->owner->xmlroot->removeChild($this->xmlroot);
            }
        }
        else
        {
            $this->xmlroot['name'] = 'tag';
            Hosts_to_xmlA($this->xmlroot['children'], $this->o, 'member', false);
            if( count($this->o) == 0 )
            {
                $this->xmlroot['name'] = 'ignme';
                $this->xmlroot['content'] = '';
            }
            //die("tags count".count($this->o)."\n");
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
        while( isset($cur->owner) && !is_null($cur->owner) )
        {
            $ref = $cur->owner;
            if( isset($ref->tagStore) &&
                !is_null($ref->tagStore)				)
            {
                $this->parentCentralStore = $ref->tagStore;
                return;
            }
            $cur = $ref;
        }

    }

}



