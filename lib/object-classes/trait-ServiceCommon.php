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

trait ServiceCommon
{
    use ReferencableObject {removeReference as super_removeReference;}

    public function isService()
    {
        return false;
    }

    public function isGroup()
    {
        return false;
    }

    public function isTmpSrv()
    {
        return false;
    }

    public function removeReference($ref)
    {
        $this->super_removeReference($ref);
    }

    /**
     * @param $objectToAdd Service|ServiceGroup
     * @param $displayOutput bool
     * @param $skipIfConflict bool
     * @param $outputPadding string|int
     */
    public function addObjectWhereIamUsed($objectToAdd, $displayOutput = false, $outputPadding = '', $skipIfConflict = false)
    {
        if( $skipIfConflict )
            derr('unsupported');

        if( !is_string($outputPadding) )
            $outputPadding = str_pad('', $outputPadding);

        foreach($this->refrules as $ref)
        {
            $refClass = get_class($ref);
            if( $refClass == 'ServiceGroup' )
            {
                /** @var ServiceGroup $ref */
                if( $displayOutput )
                    print $outputPadding."- adding in {$ref->_PANC_shortName()}\n";
                $ref->addMember($objectToAdd);
            }
            elseif( $refClass == 'ServiceRuleContainer' )
            {
                /** @var ServiceRuleContainer $ref */

                $ruleClass = get_class($ref->owner);
                if( $ruleClass == 'SecurityRule' )
                {
                    if( $displayOutput )
                        print $outputPadding."- adding in {$ref->owner->_PANC_shortName()}\n";

                    $ref->add($objectToAdd);
                }
                elseif( $ruleClass == 'NatRule' )
                {
                    derr('unsupported use case in '.$ref->_PANC_shortName());
                }
                else
                    derr('unsupported owner_class: '.$ruleClass);
            }
            else
                derr('unsupport class : '.$refClass);
        }
    }

    /**
     * @param $objectToAdd Service|ServiceGroup
     * @param $displayOutput bool
     * @param $skipIfConflict bool
     * @param $outputPadding string|int
     */
    public function API_addObjectWhereIamUsed($objectToAdd, $displayOutput = false, $outputPadding = '', $skipIfConflict = false)
    {
        if( $skipIfConflict )
            derr('unsupported');

        if( !is_string($outputPadding) )
            $outputPadding = str_pad('', $outputPadding);

        foreach($this->refrules as $ref)
        {
            $refClass = get_class($ref);
            if( $refClass == 'ServiceGroup' )
            {
                /** @var ServiceGroup $ref */
                if( $displayOutput )
                    print $outputPadding."- adding in {$ref->_PANC_shortName()}\n";
                $ref->API_addMember($objectToAdd);
            }
            elseif( $refClass == 'ServiceRuleContainer' )
            {
                /** @var ServiceRuleContainer $ref */

                $ruleClass = get_class($ref->owner);
                if( $ruleClass == 'SecurityRule' )
                {
                    if( $displayOutput )
                        print $outputPadding."- adding in {$ref->owner->_PANC_shortName()}\n";

                    $ref->API_add($objectToAdd);
                }
                elseif( $ruleClass == 'NatRule' )
                {
                    derr('unsupported use case in '.$ref->_PANC_shortName());
                }
                else
                    derr('unsupported owner_class: '.$ruleClass);
            }
            else
                derr('unsupported class : '.$refClass);
        }
    }

    /**
     * @param $displayOutput bool
     * @param $apiMode bool
     * @param $actionIfLastInRule string can be delete|setany|disable
     * @param $outputPadding string|int
     */
    private function __removeWhereIamUsed($apiMode, $displayOutput = false, $outputPadding = '', $actionIfLastInRule = 'delete' )
    {
        /** @var Service|ServiceGroup $this */

        if( is_numeric($outputPadding) )
            $outputPadding = str_pad(' ', $outputPadding);

        $allowedActionIfLastInRule = Array('delete' => true, 'setany' => true, 'disable' => true);
        if( !isset($allowedActionIfLastInRule[$actionIfLastInRule]) )
            derr('unsupported actionIfLastInRule='.$actionIfLastInRule);

        foreach($this->getReferences() as $ref)
        {
            $refClass = get_class($ref);
            if( $refClass == 'ServiceGroup' )
            {
                /** @var ServiceGroup $ref */
                if( $displayOutput )
                    print $outputPadding."- removing from {$ref->_PANC_shortName()}\n";
                if($apiMode)
                    $ref->API_removeMember($this);
                else
                    $ref->removeMember($this);
            }
            elseif( $refClass == 'ServiceRuleContainer' )
            {
                /** @var ServiceRuleContainer $ref */
                if( $ref->count() <= 1 && $actionIfLastInRule == 'delete' )
                {
                    if( $displayOutput )
                        print $outputPadding."- last member so deleting {$ref->_PANC_shortName()}\n";
                    if( $apiMode)
                        $ref->owner->owner->API_remove($ref->owner, true);
                    else
                        $ref->owner->owner->remove($ref->owner, true);
                }
                elseif( $ref->count() <= 1 && $actionIfLastInRule == 'setany' )
                {
                    if( $displayOutput )
                        print $outputPadding."- last member so setting ANY {$ref->_PANC_shortName()}\n";
                    if( $apiMode )
                        $ref->API_setAny();
                    else
                        $ref->setAny();
                }
                elseif( $ref->count() <= 1 && $actionIfLastInRule == 'disable' )
                {
                    if( $displayOutput )
                        print $outputPadding."- last member so disabling rule {$ref->_PANC_shortName()}\n";
                    if( $apiMode )
                        $ref->owner->API_setDisabled(true);
                    else
                        $ref->owner->setDisabled(true);
                }
                else
                {
                    if( $displayOutput )
                        print $outputPadding."- removing from {$ref->_PANC_shortName()}\n";
                    if( $apiMode )
                        $ref->API_remove($this);
                    else
                        $ref->remove($this);
                }
            }
            elseif( $refClass == 'NatRule' )
            {
                /** @var NatRule $ref */
                if( $actionIfLastInRule == 'delete' )
                {
                    if( $displayOutput )
                        print $outputPadding."- last member so deleting {$ref->_PANC_shortName()}\n";
                    if( $apiMode)
                        $ref->owner->API_remove($ref, true);
                    else
                        $ref->owner->remove($ref, true);
                }
                elseif( $actionIfLastInRule == 'setany' )
                {
                    if( $displayOutput )
                        print $outputPadding."- last member so setting ANY {$ref->_PANC_shortName()}\n";
                    if( $apiMode )
                        $ref->API_setService(null);
                    else
                        $ref->setService(null);
                }
                elseif( $actionIfLastInRule == 'disable' )
                {
                    if( $displayOutput )
                        print $outputPadding."- last member so disabling rule {$ref->_PANC_shortName()}\n";
                    if( $apiMode )
                        $ref->API_setDisabled(true);
                    else
                        $ref->setDisabled(true);
                }
                else
                {
                    derr('unsupported');
                }
            }
            else
                derr("unsupported class '{$refClass}'");
        }
    }

    /**
     * @param $displayOutput bool
     * @param $actionIfLastInRule string can be delete|setany|disable
     * @param $outputPadding string|int
     */
    public function removeWhereIamUsed($displayOutput = false, $outputPadding = '', $actionIfLastInRule = 'delete' )
    {
        $this->__removeWhereIamUsed(false, $displayOutput, $outputPadding, $actionIfLastInRule);
    }

    /**
     * @param bool $displayOutput
     * @param string $actionIfLastInRule can be delete|setany|disable
     * @param $outputPadding string|int
     */
    public function API_removeWhereIamUsed($displayOutput = false, $outputPadding = '', $actionIfLastInRule = 'delete' )
    {
        $this->__removeWhereIamUsed(true, $displayOutput, $outputPadding, $actionIfLastInRule);
    }



    /**
     * @param bool $displayOutput
     * @param Service|ServiceGroup $withObject
     * @param string|int $outputPadding
     */
    public function API_replaceWhereIamUsed($withObject, $displayOutput = false, $outputPadding = '')
    {
        $this->__removeWhereIamUsed(true, $withObject, $displayOutput, $outputPadding);
    }

    /**
     * @param bool $displayOutput
     * @param Service|ServiceGroup $withObject
     * @param string|int $outputPadding
     */
    public function replaceWhereIamUsed($withObject, $displayOutput = false, $outputPadding = '')
    {
        $this->__removeWhereIamUsed(false, $withObject, $displayOutput, $outputPadding);
    }


    /**
     * @param bool $displayOutput
     * @param bool $apiMode
     * @param Service|ServiceGroup $withObject
     * @param string|int $outputPadding
     */
    public function __replaceWhereIamUsed($apiMode, $withObject, $displayOutput = false, $outputPadding = '')
    {
        /** @var Service|ServiceGroup $this */

        if( is_numeric($outputPadding) )
            $outputPadding = str_pad(' ', $outputPadding);

        /** @var ServiceGroup|ServiceRuleContainer $objectRef */

        foreach( $this->refrules as $objectRef)
        {
            if( $displayOutput )
                echo $outputPadding."- replacing in {$objectRef->toString()}\n";
            if( $apiMode)
                $objectRef->API_replaceReferencedObject($this, $withObject);
            else
                $objectRef->replaceReferencedObject($this, $withObject);
        }

    }

}