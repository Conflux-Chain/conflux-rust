// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

macro_rules! make_parallel_field_maybe_in_place_byte_array_memory_manager {
    (
        $accessor_type:tt$(<$($generics:tt),+>$( where <$($constrain_item:tt: $constrain:tt),*>)?)?,
        $struct_type:path,
        $manager_field:ident,
        $byte_array_field:ident,
        $size_field:ident :
        $size_type:tt,
        $size_getter_setter_type:tt,
    ) => {
        #[derive(Default, Clone)]
        pub struct $accessor_type$($(<$($constrain_item: $constrain)*>)?)? (
            $($(std::marker::PhantomData<$generics>,)+)?
        );

        impl$($(<$($constrain_item: $constrain)*>)?)?
            ParallelFieldOffsetAccessor<
                FieldsOffsetMaybeInPlaceByteArrayMemoryManager<
                    $size_type,
                    $size_getter_setter_type,
                    $accessor_type$(<$($generics,)+>)?,
                    $accessor_type$(<$($generics,)+>)?,
                >,
                MaybeInPlaceByteArray,
            > for $accessor_type$(<$($generics,)+>)?
        {
            fn get(
                m: &FieldsOffsetMaybeInPlaceByteArrayMemoryManager<
                    $size_type,
                    $size_getter_setter_type,
                    $accessor_type$(<$($generics,)+>)?,
                    $accessor_type$(<$($generics,)+>)?,
                >,
            ) -> &MaybeInPlaceByteArray
            {
                unsafe {
                    &*(((m as *const _ as usize)
                        - memoffset::offset_of!($struct_type, $manager_field)
                        + memoffset::offset_of!($struct_type, $byte_array_field))
                        as *const MaybeInPlaceByteArray)
                }
            }

            fn get_mut(
                m: &mut FieldsOffsetMaybeInPlaceByteArrayMemoryManager<
                    $size_type,
                    $size_getter_setter_type,
                    $accessor_type$(<$($generics,)+>)?,
                    $accessor_type$(<$($generics,)+>)?,
                >,
            ) -> &mut MaybeInPlaceByteArray
            {
                unsafe {
                    &mut *(((m as *mut _ as usize)
                        - memoffset::offset_of!($struct_type, $manager_field)
                        + memoffset::offset_of!($struct_type, $byte_array_field))
                        as *mut MaybeInPlaceByteArray)
                }
            }
        }

        impl$($(<$($constrain_item: $constrain)*>)?)?
            ParallelFieldOffsetAccessor<
                FieldsOffsetMaybeInPlaceByteArrayMemoryManager<
                    $size_type,
                    $size_getter_setter_type,
                    $accessor_type$(<$($generics,)+>)?,
                    $accessor_type$(<$($generics,)+>)?,
                >,
                $size_type,
            > for $accessor_type$(<$($generics,)+>)?
        {
            fn get(
                m: &FieldsOffsetMaybeInPlaceByteArrayMemoryManager<
                    $size_type,
                    $size_getter_setter_type,
                    $accessor_type$(<$($generics,)+>)?,
                    $accessor_type$(<$($generics,)+>)?,
                >,
            ) -> &$size_type
            {
                unsafe {
                    &*(((m as *const _ as usize)
                        - memoffset::offset_of!($struct_type, $manager_field)
                        + memoffset::offset_of!($struct_type, $size_field))
                        as *const $size_type)
                }
            }

            fn get_mut(
                m: &mut FieldsOffsetMaybeInPlaceByteArrayMemoryManager<
                    $size_type,
                    $size_getter_setter_type,
                    $accessor_type$(<$($generics,)+>)?,
                    $accessor_type$(<$($generics,)+>)?,
                >,
            ) -> &mut $size_type
            {
                unsafe {
                    &mut *(((m as *mut _ as usize)
                        - memoffset::offset_of!($struct_type, $manager_field)
                        + memoffset::offset_of!($struct_type, $size_field))
                        as *mut $size_type)
                }
            }
        }
    };
}
