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
 * Class TagStore
 * @property Tag[] $o
 * @property VirtualSystem|DeviceGroup|PanoramaConf|PANConf $owner
 */
class TagStore extends ObjStore
{

    /**
     * @var null|DOMElement|string[]
     */
	public $xmlroot=null;
	protected $parentCentralStore = null;
	
	public static $childn = 'Tag';
	
	public function TagStore($owner)
	{
		$this->classn = &self::$childn;
		
		$this->owner = $owner;
		$this->o = Array();
		
		$this->findParentCentralStore();
		
	}

	
	public function find($name, $ref=null, $nested = true)
	{
		$f = $this->findByName($name,$ref);

        if( $f !== null )
            return $f;

        if( $nested && $this->parentCentralStore !== null )
            return $this->parentCentralStore->find( $name, $ref, $nested);

        return null;
	}

	public function removeAllTags()
	{
		$this->removeAll();
		$this->rewriteXML();
	}

    /**
     * add a Zone to this store. Use at your own risk.
     * @param Tag
     * @param bool
     * @return bool
     */
    public function addTag( Tag $Obj, $rewriteXML = true )
    {
        $ret = $this->add($Obj);
        if( $ret && $rewriteXML )
        {
            $this->rewriteXML();
        }
        return $ret;
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
	*
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
        //print "started to extract '".$this->toString()."' from xml\n";
        $this->xmlroot = &$xml;
        $cur = &$xml['children'];

        foreach( $cur as &$x )
        {
            $newTag = new Zone('**tmp**', $this);
            $newTag->load_from_xml($x);
            //print "found zone '".$newTag->name()."'\n";
            $this->o[] = $newTag;
        }

    }

    /**
     * should only be called from a Rule constructor
     * @ignore
     */
    public function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;

        foreach( $this->xmlroot->childNodes as $node )
        {
            if( $node->nodeType != 1 ) continue;

            $newTag = new Zone('**tmp**', $this);
            $newTag->load_from_domxml($node);
            //print $this->toString()." : new Tag '".$newTag->name()."' found\n";

            $this->o[] = $newTag;
        }
    }


    function createTag($name, $ref=null)
    {
        if( $this->find($name, null, false ) !== null )
            derr('Tag named "'.$name.'" already exists, cannot create');

        if( $this->xmlroot === null )
            return $this->createTmp($name, $ref);

        $newTag = new Tag($name, $this, true);

        if( $ref !== null )
            $newTag->refInRule($ref);

        $this->addTag($newTag);

        return $newTag;
    }

    function findOrCreate($name, $ref=null, $nested=true)
    {
        $f = $this->find($name, $ref, $nested);

        if( $f !== null )
            return $f;

        return $this->createTag($name, $ref);
    }

    function API_createTag($name, $ref=null)
    {
        $newTag = $this->createTag($name, $ref);

        if( !$newTag->isTmp() )
        {
            $xpath = $this->getXPath();
            $con = findConnectorOrDie($this);
            $con->sendSetRequest($xpath, array_to_xml( $newTag->xmlroot ,false, false));
        }

        return $newTag;
    }

    public function &getXPath()
    {
        $str = '';

        $ownerClass = get_class($this->owner);

        if( $ownerClass == 'VirtualSystem' || $ownerClass == 'DeviceGroup' )
            $str = $this->owner->getXPath();
        elseif( $ownerClass == 'PanoramaConf' )
            $str = '/config/shared';
        else
            derr('unsupported');

        $str = $str.'/tag';

        return $str;
    }


	
	public function rewriteXML()
	{
        if( $this->xmlroot === null )
            return;

        $this->xmlroot['children'] = Array();

		foreach( $this->o as $o )
        {
            if( !$o->isTmp() )
                $this->xmlroot['children'][] = &$o->xmlroot;
        }
	}
	
	
	/**
	*
	* @ignore
	*/
	protected function findParentCentralStore()
	{
		$this->parentCentralStore = null;
		
			$cur = $this->owner;
			while( isset($cur->owner) && !is_null($cur->owner) )
			{
				$ref = $cur->owner;
				if( isset($ref->tagStore) &&
					!is_null($ref->tagStore)				)
				{
					$this->parentCentralStore = $ref->tagStore;
					//print $this->toString()." : found a parent central store: ".$parentCentralStore->toString()."\n";
					return;
				}
				$cur = $ref;
			}

	}
	
}


trait centralTagStore
{
	/**
	* @var TagStore central tag store
	*/
	public $tagStore=null;
	
	/**
	* @return TagStore
	*/
	public function tagStore()
	{
		return $this->tagStore;
	}
}

