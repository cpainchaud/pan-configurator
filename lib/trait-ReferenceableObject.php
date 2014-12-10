<?php


trait ReferencableObject
{

	protected $name;
	public $refrules = Array();
	protected $refcomphash = null;
	
	protected function setRefName($newName, $skip_name_unicity_check = false)
	{
		$oldName = $this->name;
		$this->name = $newName;
		
		$this->broadcastMyNameChange($oldName);
		
	}
	
	public function refInRule($ref)
	{
		refInRule($this,$ref);
		$this->refcomphash = null;
	}
	
	public function unrefInRule($ref)
	{
		unrefInRule($this,$ref);
		$this->refcomphash = null;
	}
	
	public function broadcastMyNameChange($oldname)
	{
		
		foreach( $this->refrules as $ref )
		{
			$ref->hostChanged($this,$oldname);
		}
		
		if( $this->owner )
		{
			$this->owner->hostChanged($this,$oldname);
		}
	}
	
	public function replaceMeGlobally($newobject)
	{
		foreach( $this->refrules as $o )
		{
			$o->replaceHostObject($this, $newobject);
		}
	}
	
	
	public function countReferences()
	{
		$c = count($this->refrules);
		
		return $c;
	}
	
	public function display_references()
	{
		print "Displaying referencers for ".$this->toString()."\n";
		foreach( $this->refrules as $o )
		{
			print $o->toString()."\n";
		}
	}
	
	public function findAssociatedSecurityRules()
	{
		return $this->findAssociatedRule_byType('SecurityRule');
	}
	
	public function findAssociatedRule_byType($type)
	{
		$cur = &$this->refrules;
		$c = count($cur);
		$k = array_keys($cur);
		
		$ret = Array();
		
		for($i=0; $i<$c; $i++)
		{
			if( isset($cur[$k[$i]]->owner) && !is_null($cur[$k[$i]]->owner) )
			{
				$class = get_class($cur[$k[$i]]->owner);
				//print $cur[$k[$i]]->owner->toString()."\n";
				if( $class == $type )
				{
					if( !in_array($cur[$k[$i]]->owner, $ret, TRUE) )
					{
						$ret[] = $cur[$k[$i]]->owner;
					}
				}
				
			}
		}
		
		return $ret;
	}
	
	
	public function generateRefHashComp($force=false)
	{
		if( !is_null($this->refcomphash) && !$force )
			return;
		
		$fasthashcomp = 'ReferenceableObject';
		
		$tmpa = $this->refrules;
		
		usort($tmpa, "__CmpObjMemID");
		
		foreach( $tmpa as $o )
		{
			$fasthashcomp .= '.*/'.spl_object_hash($o);
		}
		
		$this->refcomphash = md5($fasthashcomp,true);
		
	}
	
	public function getRefHashComp()
	{
		$this->generateRefHashComp();
		return $this->refcomphash;
	}

    public function getReferencers()
    {
        return $this->refrules;
    }
	
	
	public function name()
	{
		return $this->name;
	}
	
}
