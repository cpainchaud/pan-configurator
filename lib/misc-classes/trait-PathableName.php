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
 * Class PathableName
 * @property AppStore|AddressStore|ServiceStore|RuleStore|Rule|PanoramaConf|PANConf|DeviceGroup|VirtualSystem $owner
 * @property string $name
 */
trait PathableName
{
    /**
     *
     * @return String
     */
    public function toString()
    {
        if( isset($this->name) )
            $ret = get_class($this).':'.$this->name;
        else
            $ret = get_class($this);

        if( isset($this->owner) && $this->owner !== null )
            $ret = $this->owner->toString().' / '.$ret;

        return $ret;
    }

    public function _PANC_shortName()
    {
        $str = '';

        $owner = $this;

        while( $owner !== null )
        {
            if( is_subclass_of($owner, 'ObjRuleContainer') ||
                get_class($owner) == 'DeviceGroup' || get_class($owner) == 'VirtualSystem' )
                $str = $owner->name().$str;
            elseif( is_subclass_of($owner, 'Rule') )
            {
                $str = $owner->ruleNature().':'.$owner->name().$str;
                $owner = $owner->owner;
            }
            else
            {
                if( method_exists($owner, 'name') )
                    $str = get_class($owner) . ':' . $owner->name() . $str;
                else
                    $str = get_class($owner) . $str;
            }

            $str = '/'.$str;

            if( !isset($owner->owner) )
                break;
            if( get_class($owner) == 'DeviceGroup' || get_class($owner) == 'VirtualSystem' )
                break;
            $owner = $owner->owner;
        }

        return $str;
    }

    public function getLocationString()
    {
        $obj = PH::findLocationObjectOrDie($this);
        return PH::getLocationString($obj);
    }
}
