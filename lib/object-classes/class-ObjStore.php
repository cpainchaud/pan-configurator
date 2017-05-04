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

class ObjStore
{
	use PathableName;
	use XmlConvertible;
	
	
	public $owner = null;
	public $name = '';

    /** @var null|ReferencableObject[] */
	public $o = Array();

    /** @var null|ReferencableObject[] */
	protected $nameIndex = Array();

	protected $classn=null;

    protected $skipEmptyXmlObjects = false;

	
	public function count()
	{
		return count($this->o);
	}

	public function countUnused()
	{
		$count = 0;
		foreach( $this->o as $o )
		{
			if( $o->countReferences() == 0 )
				$count++;
		}

		return $count;
	}
	
	public function setName($newname)
	{
		$this->name = $newname;
	}
	
	protected function findByName($name, $ref=null)
	{
		if( isset($this->nameIndex[$name]) )
		{
			$o = $this->nameIndex[$name];
			if( $ref !== null )
				$o->addReference($ref);
			return $o;
		}

		return null;
	}
	
	
	/**
	* Returns 'true' if this object is in the store
	*
	*/
	public function inStore($Obj)
	{
		if( in_array($Obj,$this->o,true) )
		{
			return true;
		}
		
		return false;
	}


	
	/**
	* search for object with its name and returns it. If it doesn't exist, create it and return it.
	*
	*/
	public function findOrCreate($name, $ref=null)
	{
		$f = $this->findByName($name,$ref);
		
		if( $f !== null )
			return $f;
		
		$f = $this->createTmp($name, $ref);
		
		return $f;	
	}
	
	function createTmp($name, $ref=null)
	{

		$f = new $this->classn($name,$this);
        /** @var ReferencableObject $f */

		$this->o[] = $f;
		$this->nameIndex[$name] = $f;
		$f->type = 'tmp';
		$f->addReference($ref);
		
		return $f;
	}

	
	/**
	*
	*
	*/
	public function display($indentSpace = 0)
	{
		$indent = '';
		
		for( $i=0; $i<$indentSpace; $i++ )
		{
			$indent .= ' ';
		}
		
		$c = count($this->o);
		$k = array_keys($this->o);
		
		echo "$indent";
		print "Displaying the $c ".$this->classn."(s) in ".$this->toString()."\n";
		
		for( $i=0; $i<$c ;$i++)
		{
			print $indent.$this->o[$k[$i]]->name."\n";
		}
	}

    /**
     * @param ReferencableObject $h
     * @param string $oldName
     * @throws Exception
     */
	public function referencedObjectRenamed($h, $oldName)
	{
		if(isset($this->nameIndex[$h->name()]))
		{
			derr("an object with this name already exists in this store");
		}

		if( isset($this->nameIndex[$oldName]) )
		{
			$o = $this->nameIndex[$oldName];
			if($o === $h)
			{
				unset($this->nameIndex[$oldName]);
				$this->nameIndex[$h->name()] = $h;
			}
			else
				mwarning("tried to broadcast name change to a Store that doesnt own this object");
		}
		else
			mwarning("object with name '{$oldName}' was not part of this store/index");
	}


    /**
     * @ignore
     * @param ReferencableObject $Obj
     * @return bool
     */
	protected function add($Obj)
	{	
		if( !in_array($Obj,$this->o,true) )
		{
			$this->o[] = $Obj;
			$this->nameIndex[$Obj->name()] = $Obj;
			$Obj->owner = $this;

			return true;
		}
		
		return false;
	}

	protected function removeAll()
	{
		foreach( $this->o as $o)
		{
			$o->owner = null;
		}

		$this->o = Array();
		$this->nameIndex = Array();
	}

    /**
     * @param ReferencableObject $Obj
     * @return bool
     */
	protected function remove($Obj)
	{
		$pos = array_search($Obj,$this->o,true);
		if( $pos !== FALSE )
		{
			unset($this->o[$pos]);
			unset($this->nameIndex[$Obj->name()]);
			$Obj->owner = null;

			return true;
		}
		
		return false;
	}
	
	/**
	* Returns an array with all objects in store
	* @return array
	*/
	public function getAll()
	{
		return $this->o;
	}


	public function rewriteXML()
	{
        if( $this->xmlroot !== null )
        {
            DH::clearDomNodeChilds($this->xmlroot);
            foreach($this->o as $o)
            {
                $this->xmlroot->appendChild($o->xmlroot);
            }
        }
	}


	/**
	 * should only be called from a store constructor
	 * @ignore
	 */
	public function load_from_domxml(DOMElement $xml)
	{
		$this->xmlroot = $xml;

		foreach( $this->xmlroot->childNodes as $node )
		{
			if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            /** @var DOMElement $node */

            if( $this->skipEmptyXmlObjects && !$node->hasChildNodes() )
            {
                mwarning('XML element had no child, it was skipped', $node);
                continue;
            }

			//print $this->toString()."\n";
			$newObj = new $this->classn('**tmp**', $this);
			$newObj->load_from_domxml($node);
			//print $this->toString()." : new Tag '".$newTag->name()."' found\n";

			$this->o[] = $newObj;
			$this->nameIndex[$newObj->name()] = $newObj;
		}
	}


}

